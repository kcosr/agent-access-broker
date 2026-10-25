//! Generic, bounded MCP imports through the broker's ordinary provider boundary.
mod oauth;
mod protocol;
mod schema;
mod transport;

use agent_access_core::imports::*;
use agent_access_provider::*;
use async_trait::async_trait;
use base64::{Engine, prelude::BASE64_STANDARD};
use http::HeaderName;
use protocol::{LEGACY_PROTOCOL_VERSION, Lifecycle};
use rmcp::{
    RoleClient,
    model::{
        CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation,
        PaginatedRequestParams, ProtocolVersion,
    },
    service::{ClientLifecycleMode, RunningService, serve_client_with_lifecycle_and_ct},
};
use schema::CompiledSchema;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use transport::{CallArguments, Operation, WireClient, WireState, protocol_error};
use url::Url;

pub use transport::PROTOCOL_VERSION;

/// The `mcp_http` import selection, with its `mcp_oauth` companion dialect
/// as the import-authentication role. Selecting it registers that dialect;
/// an assembly must not select the dialect separately.
pub fn registration() -> ImportedAdapterRegistration {
    imported_adapter_registration(
        agent_access_provider::module_metadata!(),
        &McpAdapter,
        Some(oauth::IMPORT_AUTHENTICATION),
    )
}

#[derive(Debug)]
struct McpAdapter;

#[async_trait]
impl ImportedAdapter for McpAdapter {
    fn credential_contract(
        &self,
        definition: &ImportedServiceDefinition,
        _import: &ImportedAdapterContext<'_>,
    ) -> Result<ImportedCredentialContract, String> {
        self.validate_definition(definition)?;
        Ok(ImportedCredentialContract::new(
            definition
                .execution_bindings
                .iter()
                .any(|b| b.mechanism == ImportedAuthMechanism::StaticToken)
                .then(ImportedCredentialRequirement::token_header),
            matches!(definition.discovery, ImportedDiscoveryCredential::Slot)
                .then(ImportedCredentialRequirement::token_header),
            definition
                .transport_auth
                .then(ImportedCredentialRequirement::token_header),
        ))
    }
    fn validate_definition(&self, definition: &ImportedServiceDefinition) -> Result<(), String> {
        definition.validate()?;
        if !definition.connection_settings.is_empty()
            || matches!(definition.discovery, ImportedDiscoveryCredential::Anonymous)
            || definition.execution_bindings.iter().any(|b| {
                !matches!(
                    b.delivery,
                    ImportedCredentialDelivery::Bearer
                        | ImportedCredentialDelivery::RawHeader { .. }
                )
            })
        {
            return Err(
                "MCP imports require header-token delivery and authenticated discovery".into(),
            );
        }
        Ok(())
    }
    fn kind(&self) -> &'static str {
        "mcp_http"
    }

    fn development_only(&self) -> bool {
        false
    }

    fn sensitive_output_pointers(&self) -> &'static [&'static str] {
        &["/result/upstreamMcp"]
    }

    fn validate_action(&self, action: &ImportedActionDefinition) -> Result<(), String> {
        CompiledAction::new(action).map(|_| ())
    }

    fn scoped_mcp_name(&self, action: &ImportedActionDefinition) -> Result<String, String> {
        source_tool_name(action).map(str::to_owned)
    }

    fn build(
        &self,
        definition: &ImportedServiceDefinition,
        actions: &[ImportedActionDefinition],
        transport_credential: Option<ExecutionCredential>,
        _import: &ImportedAdapterContext<'_>,
        host: &BuildContext<'_>,
    ) -> Result<ImportedProvider, ProviderBuildError> {
        self.validate_definition(definition)
            .map_err(ProviderBuildError::invalid)?;
        let mut compiled = BTreeMap::new();
        for action in actions {
            self.scoped_mcp_name(action)
                .map_err(ProviderBuildError::invalid)?;
            let value = CompiledAction::new(action).map_err(ProviderBuildError::invalid)?;
            if compiled.insert(action.action.clone(), value).is_some() {
                return Err(ProviderBuildError::invalid("duplicate imported action"));
            }
        }
        Ok(ImportedProvider::Upstream(Arc::new(McpProvider {
            wire: make_wire(definition, host)?,
            definition: definition.clone(),
            actions: compiled,
            transport_credential,
            timeout: Duration::from_millis(host.limits().request_timeout_ms),
        })))
    }

    async fn discover(
        &self,
        definition: &ImportedServiceDefinition,
        authentication: &ImportedDiscoveryAuthentication,
        transport_credential: Option<ExecutionCredential>,
        _import: &ImportedAdapterContext<'_>,
        host: &BuildContext<'_>,
    ) -> Result<ImportedDiscovery, AdapterDiscoveryError> {
        let wire = make_wire(definition, host).map_err(|_| {
            AdapterDiscoveryError::Configuration(
                "imported MCP endpoint could not be prepared".to_owned(),
            )
        })?;
        let delivery = &definition
            .execution_bindings
            .first()
            .ok_or_else(credential_error)?
            .delivery;
        let (auth, delegated) = match authentication {
            ImportedDiscoveryAuthentication::Static(credential) => (
                static_authorization(
                    definition,
                    delivery,
                    credential,
                    transport_credential.as_ref(),
                )?,
                None,
            ),
            ImportedDiscoveryAuthentication::Delegated(credential)
                if matches!(
                    definition.discovery,
                    ImportedDiscoveryCredential::PerUser { .. }
                ) && !definition.transport_auth
                    && transport_credential.is_none()
                    && definition.execution_bindings.iter().any(|binding| {
                        binding.owner_mode == ImportedCredentialMode::PerUser
                            && binding.mechanism == ImportedAuthMechanism::Oauth
                            && binding.is_supported()
                    }) =>
            {
                (Vec::new(), Some(credential.clone()))
            }
            _ => return Err(credential_error().into()),
        };
        Ok(discover(wire, auth, delegated, &definition.endpoint).await?)
    }
}

fn make_wire(
    definition: &ImportedServiceDefinition,
    host: &BuildContext<'_>,
) -> Result<WireClient, ProviderBuildError> {
    McpAdapter
        .validate_definition(definition)
        .map_err(ProviderBuildError::invalid)?;
    if definition.adapter_kind != "mcp_http" {
        return Err(ProviderBuildError::invalid(
            "incorrect imported adapter kind",
        ));
    }
    let endpoint = Url::parse(&definition.endpoint)
        .map_err(|_| ProviderBuildError::invalid("invalid imported endpoint"))?;
    let client = UpstreamClient::build(
        UpstreamClientSpec::new(
            "imports.mcp_http",
            "mcp_http",
            &endpoint,
            EgressDeclaration::Ordinary(None),
            std::slice::from_ref(&definition.endpoint),
            ClientProfile::SingleAttempt,
        ),
        host.clients(),
    )?;
    Ok(WireClient {
        client: Arc::new(client),
        endpoint,
        service: definition.service.clone(),
        max_bytes: host.limits().max_upstream_response_bytes,
    })
}

struct CompiledAction {
    definition: ImportedActionDefinition,
    name: String,
    input: CompiledSchema,
    output: Option<CompiledSchema>,
}

fn source_tool_name(definition: &ImportedActionDefinition) -> Result<&str, String> {
    let source = definition
        .source
        .as_object()
        .ok_or("tool source must be an object")?;
    if source.len() != 1 {
        return Err("MCP source supports only toolName".into());
    }
    source
        .get("toolName")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| "MCP source requires a bounded toolName".into())
}

impl CompiledAction {
    fn new(definition: &ImportedActionDefinition) -> Result<Self, String> {
        if definition.download {
            return Err("MCP imports do not support download actions".into());
        }
        if serde_json::to_vec(definition)
            .map_err(|_| "invalid tool definition")?
            .len()
            > schema::MAX_TOOL_BYTES
            || definition.description.len() > schema::MAX_DESCRIPTION_BYTES
        {
            return Err("tool definition exceeds import limits".into());
        }
        let name = source_tool_name(definition)?.to_owned();
        Ok(Self {
            definition: definition.clone(),
            name,
            input: CompiledSchema::input(&definition.input_schema)?,
            output: definition
                .output_schema
                .as_ref()
                .map(CompiledSchema::output)
                .transpose()?,
        })
    }
}

struct McpProvider {
    wire: WireClient,
    definition: ImportedServiceDefinition,
    actions: BTreeMap<String, CompiledAction>,
    transport_credential: Option<ExecutionCredential>,
    timeout: Duration,
}

impl McpProvider {
    /// Imported actions are action-only; their inputs must match the tool schema.
    fn validate_action_inputs(&self, action: &str, inputs: &Value) -> Result<(), ProviderError> {
        let action = self.actions.get(action).ok_or_else(input_error)?;
        if !action.input.valid(inputs) {
            return Err(input_error());
        }
        action.input.headers(inputs).map_err(|_| input_error())?;
        Ok(())
    }
}

#[async_trait]
impl Provider for McpProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.validate_action_inputs(request.action(), request.inputs())?;
        Ok(ScopeResolution::no_resources())
    }

    async fn verify_execution_credential(
        &self,
        credential: &ExecutionCredential,
        correlation: &CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        let started = Instant::now();
        let delivery = &self
            .definition
            .execution_bindings
            .first()
            .ok_or_else(credential_error)?
            .delivery;
        let auth = static_authorization(
            &self.definition,
            delivery,
            credential,
            self.transport_credential.as_ref(),
        )?;
        agent_access_provider::host::with_correlation_context(correlation.clone(), async {
            let discovered =
                discover(self.wire.clone(), auth, None, &self.definition.endpoint).await?;
            Ok(Some(ProviderCredentialVerification::new(
                200,
                started.elapsed().as_millis() as u64,
                json!({"adapterKind":"mcp_http", "protocolVersion":discovered.protocol_version}),
            )))
        })
        .await
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.validate_action_inputs(request.action(), request.inputs())?;
        if request.service() != self.definition.service
            || !matches!(request.authority(), InvocationAuthority::ActionOnly)
            || !request.body_parts().is_empty()
        {
            return Err(input_error());
        }
        let binding = self
            .definition
            .execution_bindings
            .iter()
            .find(|binding| {
                binding.owner_mode.as_str() == request.credential_mode().as_str()
                    && binding.is_supported()
            })
            .ok_or_else(credential_error)?;
        let action = self.actions.get(request.action()).ok_or_else(input_error)?;
        let auth = match binding.mechanism {
            ImportedAuthMechanism::StaticToken if request.execution().delegated().is_none() => {
                static_authorization(
                    &self.definition,
                    &binding.delivery,
                    request
                        .execution()
                        .static_credential()
                        .ok_or_else(credential_error)?,
                    self.transport_credential.as_ref(),
                )?
            }
            ImportedAuthMechanism::Oauth
                if request.execution().delegated().is_some()
                    && binding.owner_mode == ImportedCredentialMode::PerUser
                    && binding.delivery == ImportedCredentialDelivery::Bearer
                    && !self.definition.transport_auth =>
            {
                Vec::new()
            }
            _ => return Err(credential_error()),
        };
        let (modern_arguments, headers) = action
            .input
            .arguments_and_headers(request.inputs())
            .map_err(|_| input_error())?;
        let call = CallArguments {
            name: action.name.clone(),
            arguments: request.inputs().clone(),
            modern_arguments,
            headers,
        };
        let operation = Operation::new(
            self.wire.clone(),
            auth,
            request
                .execution()
                .delegated()
                .cloned()
                .map(|credential| (credential, self.definition.endpoint.clone())),
            Some(call),
            self.timeout,
        );
        let state = Arc::clone(&operation.state);
        let started = Instant::now();
        let work = async {
            let client = connect(&operation).await?;
            // Real names/arguments stay inside HostTransport, away from SDK trace events.
            let result = client
                .peer()
                .call_tool_once(
                    CallToolRequestParams::new("imported_tool").with_arguments(Default::default()),
                )
                .await;
            let raw = if result.is_err() {
                Err(operation.error())
            } else {
                take_result(&state)
            };
            let _ = client.cancel().await;
            normalize_result(raw?, action)
        };
        let outcome = operation
            .run(work, "imported MCP invocation exceeded its deadline")
            .await;
        let state = state.lock().expect("wire state");
        let elapsed = started.elapsed().as_millis() as u64;
        let mut audit = json!({"adapterKind":"mcp_http", "upstreamTool":action.name,
            "credentialMode":request.credential_mode(),
            "toolDispatched":state.call_dispatched});
        if let Some(version) = state.protocol_version {
            audit["protocolVersion"] = json!(version);
        }
        match outcome {
            Ok(mut result) => {
                if !action.definition.read_only {
                    result["mutationStatus"] = json!("applied_unverified");
                    result["retrySafe"] = json!(false);
                }
                Ok(ProviderResult::new(result)
                    .with_audit(audit)
                    .with_upstream(state.status, Some(elapsed)))
            }
            Err(mut error) => {
                if !action.definition.read_only {
                    // A tool call that was never dispatched, or that the SDK
                    // refused or proved unsent, applied nothing; anything
                    // else may have been applied.
                    error = error.with_mutation_receipt(if state.call_dispatched {
                        MutationReceipt::unknown()
                    } else {
                        MutationReceipt::not_applied()
                    });
                    if let Some(result) = error.result.as_deref_mut() {
                        result["toolDispatched"] = json!(state.call_dispatched);
                    }
                }
                Err(error
                    .with_upstream(state.status, Some(elapsed))
                    .with_audit(audit))
            }
        }
    }
}

fn input_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "imported action inputs do not match the accepted definition",
    )
}
fn credential_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialInvalid,
        "imported service requires a supported configured token credential",
    )
}

/// The static credentials every request of one operation presents, in order:
/// the execution token in its delivery, then any transport token as
/// `Authorization: Bearer`. The SDK checks and presents each token.
fn static_authorization(
    definition: &ImportedServiceDefinition,
    delivery: &ImportedCredentialDelivery,
    execution: &ExecutionCredential,
    transport: Option<&ExecutionCredential>,
) -> Result<Vec<UpstreamAuthorization>, ProviderError> {
    delivery.validate().map_err(|_| credential_error())?;
    let placement = match delivery {
        ImportedCredentialDelivery::Bearer => CredentialPlacement::bearer(),
        ImportedCredentialDelivery::RawHeader { name } => CredentialPlacement::header(
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| credential_error())?,
        ),
        // Stdin delivery belongs to command imports, never to HTTP.
        ImportedCredentialDelivery::Stdin | ImportedCredentialDelivery::Basic => {
            return Err(credential_error());
        }
    };
    let mut authorization = vec![
        execution
            .authorization_as(&placement)
            .map_err(|_| credential_error())?,
    ];
    if definition.transport_auth {
        if matches!(delivery, ImportedCredentialDelivery::Bearer) {
            return Err(credential_error());
        }
        authorization.push(
            transport
                .ok_or_else(credential_error)?
                .authorization_as(&CredentialPlacement::bearer())
                .map_err(|_| credential_error())?,
        );
    }
    Ok(authorization)
}

async fn connect(
    operation: &Operation,
) -> Result<RunningService<RoleClient, ClientConfig>, ProviderError> {
    let info = |version| {
        ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new(HOST_IMPLEMENTATION.name, HOST_IMPLEMENTATION.version),
        )
        .with_protocol_version(version)
    };
    let (transport, cancel) = operation.attempt(Lifecycle::Discover);
    match serve_client_with_lifecycle_and_ct(
        info(ProtocolVersion::V_2026_07_28),
        transport,
        ClientLifecycleMode::Discover {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
        },
        cancel,
    )
    .await
    {
        Ok(client) => return Ok(client),
        Err(_) if operation.begin_legacy()? => {}
        Err(_) => return Err(operation.error()),
    }
    let (transport, cancel) = operation.attempt(Lifecycle::Initialize);
    serve_client_with_lifecycle_and_ct(
        info(ProtocolVersion::V_2025_11_25),
        transport,
        ClientLifecycleMode::Initialize,
        cancel,
    )
    .await
    .map_err(|_| operation.error())
}
fn take_result(state: &Mutex<WireState>) -> Result<Value, ProviderError> {
    state
        .lock()
        .expect("wire state")
        .result
        .take()
        .ok_or_else(protocol_error)
}

async fn discover(
    mut wire: WireClient,
    auth: Vec<UpstreamAuthorization>,
    delegated: Option<DelegatedCredential>,
    resource: &str,
) -> Result<ImportedDiscovery, ProviderError> {
    // Discovery has its own manifest ceiling, never a larger per-request allowance.
    wire.max_bytes = wire.max_bytes.min(IMPORT_MAX_MANIFEST_BYTES as u64);
    let operation = Operation::new(
        wire,
        auth,
        delegated.map(|credential| (credential, resource.to_owned())),
        None,
        Duration::from_secs(60),
    );
    operation
        .run(
            discover_tools(&operation),
            "imported MCP discovery exceeded its deadline",
        )
        .await
}

async fn discover_tools(operation: &Operation) -> Result<ImportedDiscovery, ProviderError> {
    let state = &operation.state;
    let client = connect(operation).await?;
    let version = state
        .lock()
        .expect("wire state")
        .protocol_version
        .ok_or_else(protocol_error)?;
    let discovered = take_result(state)?;
    // Only standardized implementation identity is useful to an administrator.
    // Opaque extensions, instructions, icons and links never enter the manifest.
    let mut server_info = serde_json::Map::new();
    let info = if version == LEGACY_PROTOCOL_VERSION {
        discovered.get("serverInfo")
    } else {
        discovered.pointer("/_meta/io.modelcontextprotocol~1serverInfo")
    };
    if let Some(info) = info {
        for field in ["name", "version", "title"] {
            if let Some(value) = info.get(field).and_then(Value::as_str)
                && !value.is_empty()
                && value.len() <= 512
                && !value.chars().any(char::is_control)
            {
                server_info.insert(field.into(), json!(value));
            }
        }
    }
    let server_info = if server_info.is_empty() {
        Value::Null
    } else {
        Value::Object(server_info)
    };
    let result = async {
        let mut tools = Vec::new();
        let mut names = BTreeSet::new();
        let mut cursors = BTreeSet::new();
        let mut bytes = 0usize;
        let mut listing_metadata = Vec::new();
        for page in 0..128 {
            // Every SDK cache key is unique, while actual cursors remain transport-owned.
            let mut params = PaginatedRequestParams::default();
            params.cursor = Some(format!("page-{page}"));
            client
                .peer()
                .list_tools(Some(params))
                .await
                .map_err(|_| operation.error())?;
            let raw = take_result(state)?;
            bytes = bytes
                .checked_add(
                    serde_json::to_vec(&raw)
                        .map_err(|_| protocol_error())?
                        .len(),
                )
                .ok_or_else(protocol_error)?;
            if bytes > IMPORT_MAX_MANIFEST_BYTES {
                return Err(protocol_error());
            }
            // Preserve source cache declarations only as bounded metadata. This
            // operation never shares or reuses a user's upstream response.
            let mut cache = serde_json::Map::new();
            for field in ["cacheScope", "ttlMs"] {
                if let Some(value) = raw.get(field) {
                    cache.insert(field.into(), value.clone());
                }
            }
            listing_metadata.push(Value::Object(cache));
            for tool in raw
                .get("tools")
                .and_then(Value::as_array)
                .ok_or_else(protocol_error)?
            {
                if tools.len() >= IMPORT_MAX_TOOLS {
                    return Err(protocol_error());
                }
                let name = tool
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(protocol_error)?;
                if !names.insert(name.to_owned()) {
                    return Err(protocol_error());
                }
                // JSON Schema compilation is synchronous. Keep it off runtime
                // workers and bound cancellation to one in-progress tool.
                let tool = tool.clone();
                tools.push(tokio::task::spawn_blocking(move || discovered_tool(&tool))
                    .await.map_err(|_| protocol_error())??);
            }
            let cursor = raw.get("nextCursor").and_then(Value::as_str);
            match cursor {
                None => {
                    return Ok(ImportedDiscovery {
                        protocol_version: version.into(),
                        metadata: json!({"adapterKind":"mcp_http", "pages":page + 1, "listings":listing_metadata, "serverInfo":server_info}),
                        tools,
                        service_metadata: None,
                        resource_type_changes: Vec::new(),
                    });
                }
                Some(cursor)
                    if cursor.len() <= 16 * 1024
                        && !cursor.is_empty()
                        && cursors.insert(cursor.to_owned()) =>
                {
                    state.lock().expect("wire state").cursor = Some(cursor.to_owned());
                }
                Some(_) => return Err(protocol_error()),
            }
        }
        Err(protocol_error())
    }
    .await;
    let _ = client.cancel().await;
    result
}

fn discovered_tool(raw: &Value) -> Result<ImportedDiscoveredTool, ProviderError> {
    let name = raw
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(protocol_error)?;
    let definition = ImportedActionDefinition {
        action: "pending".into(),
        source: json!({"toolName":name}),
        label: raw.get("title").and_then(Value::as_str).map(str::to_owned),
        description: raw
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        input_schema: raw.get("inputSchema").cloned().unwrap_or(Value::Null),
        output_schema: raw.get("outputSchema").cloned(),
        annotations: json!({"toolAnnotations":raw.get("annotations").cloned().unwrap_or_else(|| json!({})),
            "execution":raw.get("execution").cloned().unwrap_or(Value::Null)}),
        read_only: false,
        download: false,
    };
    let unsupported_reason =
        if serde_json::to_vec(raw).map_err(|_| protocol_error())?.len() > IMPORT_MAX_TOOL_BYTES {
            Some("tool definition exceeds import limits".into())
        } else if raw
            .get("execution")
            .and_then(|e| e.get("taskSupport"))
            .and_then(Value::as_str)
            == Some("required")
        {
            Some("tool requires unsupported background task execution".into())
        } else if serde_json::from_value::<rmcp::model::Tool>(raw.clone()).is_err() {
            Some("tool definition has invalid MCP field types".into())
        } else {
            CompiledAction::new(&definition).err()
        };
    Ok(ImportedDiscoveredTool {
        read_only_hint: raw
            .pointer("/annotations/readOnlyHint")
            .and_then(Value::as_bool),
        definition,
        unsupported_reason,
    })
}

fn normalize_result(raw: Value, action: &CompiledAction) -> Result<Value, ProviderError> {
    // Explicit null is deliberately tested and copied from raw, because SDK Option<Value>
    // collapses it into absence. Typed content parsing checks every standard block shape.
    if raw.get("content").is_some_and(|v| !v.is_array())
        || raw.get("isError").is_some_and(|v| !v.is_boolean())
    {
        return Err(protocol_error());
    }
    let mut for_validation = raw.clone();
    for_validation
        .as_object_mut()
        .ok_or_else(protocol_error)?
        .entry("content")
        .or_insert_with(|| json!([]));
    let result: rmcp::model::CallToolResult =
        serde_json::from_value(for_validation).map_err(|_| protocol_error())?;
    let failed = result.is_error.unwrap_or(false);
    if !failed && let Some(schema) = &action.output {
        let structured = raw.get("structuredContent").ok_or_else(protocol_error)?;
        if !schema.valid(structured) {
            return Err(protocol_error());
        }
    }
    let mut content = serde_json::to_value(result.content).map_err(|_| protocol_error())?;
    for block in content.as_array_mut().ok_or_else(protocol_error)? {
        drop_protocol_meta(block);
        if let Some(encoded) = block
            .get("data")
            .or_else(|| block.pointer("/resource/blob"))
            .and_then(Value::as_str)
        {
            // Already bounded by the encoded HTTP body; decoding cannot enlarge that bound.
            BASE64_STANDARD
                .decode(encoded)
                .map_err(|_| protocol_error())?;
        }
    }
    let mut upstream = json!({"content":content,"isError":failed});
    if let Some(structured) = raw.get("structuredContent") {
        upstream["structuredContent"] = structured.clone();
    }
    let result = json!({"upstreamMcp":upstream});
    if failed {
        Err(ProviderError::error(
            ReasonCode::UpstreamFailed,
            "upstream MCP tool reported an error",
        )
        .with_result(result))
    } else {
        Ok(result)
    }
}

fn drop_protocol_meta(value: &mut Value) {
    if let Value::Object(fields) = value {
        fields.remove("_meta");
        if let Some(resource) = fields.get_mut("resource") {
            drop_protocol_meta(resource);
        }
    }
}

#[cfg(test)]
mod tests;
