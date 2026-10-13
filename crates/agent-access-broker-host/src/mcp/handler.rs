use super::{Admitted, Endpoint, output};
use crate::{
    handlers::data::{admit_mcp_invoke, invoke_admitted_json},
    state::AppState,
};
use agent_access_core::{
    ApiCatalog, InvocationControl, InvokeRequest, ResourceListQuery,
    mcp::{self, McpView, ProjectionMode, ToolRegistry, ToolTarget},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig, Tool,
    },
    service::RequestContext,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    time::{Duration, Instant},
};
use tracing::Instrument;

#[derive(Clone)]
pub(super) struct Handler {
    endpoint: Endpoint,
    view: McpView,
}
/// Discovery is prepared at the HTTP edge after queued proof verification, so
/// identity failures retain their canonical outer HTTP status before the SDK.
#[derive(Clone)]
pub(super) enum PreparedDiscovery {
    List(Result<ListToolsResult, ErrorData>),
    Helper(Result<CallToolResult, ErrorData>),
}
impl Handler {
    pub fn new(endpoint: Endpoint, view: McpView) -> Self {
        Self { endpoint, view }
    }
    fn admitted(&self, context: &RequestContext<RoleServer>) -> Result<Admitted, ErrorData> {
        context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<Admitted>())
            .filter(|request| request.view == self.view)
            .cloned()
            .ok_or_else(|| ErrorData::internal_error("Missing Broker request admission", None))
    }
    fn catalog(request: &Admitted) -> ApiCatalog {
        let mut catalog = agent_access_core::empty_catalog(json!({}));
        catalog.services = request.snapshot.runtime.api_services_for_mcp_view(
            &request.identity,
            &request.context,
            &request.view,
        );
        catalog
    }
    fn registry(request: &Admitted, catalog: &ApiCatalog) -> Result<ToolRegistry, ErrorData> {
        ToolRegistry::build(
            catalog,
            &request.view,
            ProjectionMode::Http,
            request.snapshot.runtime.config().mcp.max_catalog_bytes,
        )
        .map_err(|_| {
            ErrorData::internal_error(
                if request.view.service().is_some() {
                    "Service MCP view is unavailable"
                } else {
                    "Broker catalog projection failed"
                },
                None,
            )
        })
    }
    pub(super) fn validate_view(request: &Admitted) -> Result<(), ErrorData> {
        let catalog = Self::catalog(request);
        Self::registry(request, &catalog).map(|_| ())
    }
    pub(super) fn prepare_discovery(
        &self,
        request: &Admitted,
        message: &Value,
    ) -> Option<PreparedDiscovery> {
        match message["method"].as_str()? {
            "tools/list" => {
                let params = serde_json::from_value::<Option<PaginatedRequestParams>>(
                    message.get("params").cloned().unwrap_or(Value::Null),
                );
                Some(PreparedDiscovery::List(match params {
                    Ok(params) => {
                        self.tools(request, params.as_ref().and_then(|p| p.cursor.as_deref()))
                    }
                    Err(_) => Err(ErrorData::invalid_params(
                        "Invalid discovery parameters",
                        None,
                    )),
                }))
            }
            "tools/call"
                if message["params"]["name"]
                    .as_str()
                    .is_some_and(mcp::is_helper) =>
            {
                let prepare = || {
                    let params =
                        serde_json::from_value::<CallToolRequestParams>(message["params"].clone())
                            .map_err(|_| {
                                ErrorData::invalid_params("Invalid discovery parameters", None)
                            })?;
                    let catalog = Self::catalog(request);
                    let registry = Self::registry(request, &catalog)?;
                    let Some(ToolTarget::Helper(helper)) = registry.resolve(&params.name) else {
                        return Err(ErrorData::invalid_params(
                            "Unknown or unavailable HTTP MCP tool",
                            None,
                        ));
                    };
                    let limit = request.snapshot.runtime.config().mcp.max_response_bytes;
                    Ok(match self.helper(request, &catalog, &registry, helper.as_str(), params.arguments.unwrap_or_default()) {
                        Ok(value) => output::result(value, false, limit).unwrap_or_else(|_| output::message(
                            "Discovery result exceeds MCP response limit; use narrower discovery",
                        )),
                        Err(message) => output::message(message),
                    })
                };
                Some(PreparedDiscovery::Helper(prepare()))
            }
            _ => None,
        }
    }
    fn tools(
        &self,
        request: &Admitted,
        cursor: Option<&str>,
    ) -> Result<ListToolsResult, ErrorData> {
        let catalog = Self::catalog(request);
        let registry = Self::registry(request, &catalog)?;
        let mut definitions = registry.definitions();
        definitions.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        let config = &request.snapshot.runtime.config().mcp;
        // One bounded serialization per definition supplies both the catalog
        // fingerprint and page accounting. Never serialize each growing prefix.
        let mut hash = Sha256::new();
        let mut remaining = config.max_catalog_bytes;
        let mut tools = Vec::with_capacity(definitions.len());
        for definition in definitions {
            let tool: Tool = serde_json::from_value(definition)
                .map_err(|_| ErrorData::internal_error("Invalid Broker tool schema", None))?;
            let bytes = output::serialize(&tool, remaining).map_err(|_| {
                ErrorData::internal_error("Broker catalog exceeds MCP work limit", None)
            })?;
            remaining = remaining
                .checked_sub(bytes.len().saturating_add(1))
                .ok_or_else(|| {
                    ErrorData::internal_error("Broker catalog exceeds MCP work limit", None)
                })?;
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(&bytes);
            tools.push((tool, bytes.len()));
        }
        let fingerprint = format!("{:x}", hash.finalize());
        let invalid = || {
            ErrorData::invalid_params("Invalid or stale catalog cursor; restart tools/list", None)
        };
        // Bind cursors to authority without exporting the credential fingerprint.
        let signature_input = |bytes: &[u8]| {
            serde_json::to_vec(&(
                &request.owner,
                request.context.as_str(),
                &request.view,
                bytes,
            ))
            .unwrap()
        };
        let offset = if let Some(cursor) = cursor {
            if cursor.len() > 1024 {
                return Err(invalid());
            }
            let (encoded, signature) = cursor.split_once('.').ok_or_else(invalid)?;
            let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid())?;
            if !self
                .endpoint
                .valid_signature(&signature_input(&bytes), signature)
            {
                return Err(invalid());
            }
            let (expected, offset): (String, usize) =
                serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if expected != fingerprint || offset == 0 || offset >= tools.len() {
                return Err(invalid());
            }
            offset
        } else {
            0
        };
        let total = tools.len();
        let mut result = ListToolsResult::with_all_items(Vec::new());
        // Reserve the tools/cursor wrapper in addition to JSON-RPC/SSE framing.
        // The cursor is capped at 1024 bytes and does not contain arbitrary text.
        let page_budget = config
            .max_response_bytes
            .saturating_sub(output::WIRE_RESERVE + 1024);
        let mut page_bytes = 0usize;
        for (tool, bytes) in tools.into_iter().skip(offset).take(100) {
            let next = page_bytes.saturating_add(bytes).saturating_add(1);
            if next > page_budget {
                if result.tools.is_empty() {
                    return Err(ErrorData::internal_error(
                        "A Broker tool definition exceeds MCP response limit",
                        None,
                    ));
                }
                break;
            }
            page_bytes = next;
            result.tools.push(tool);
        }
        let end = offset + result.tools.len();
        if end < total {
            let bytes = serde_json::to_vec(&(&fingerprint, end)).unwrap();
            result.next_cursor = Some(format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(&bytes),
                self.endpoint.signature(&signature_input(&bytes))
            ));
        }
        // Final defense against future SDK envelope changes; checked only once.
        output::serialize(
            &result,
            config
                .max_response_bytes
                .saturating_sub(output::WIRE_RESERVE),
        )
        .map_err(|_| {
            ErrorData::internal_error("Broker tool page exceeds MCP response limit", None)
        })?;
        Ok(result)
    }
    fn helper(
        &self,
        request: &Admitted,
        catalog: &ApiCatalog,
        registry: &ToolRegistry,
        name: &str,
        args: Map<String, Value>,
    ) -> Result<Value, &'static str> {
        mcp::validate_helper_arguments_for_view(name, &args, ProjectionMode::Http, &request.view)
            .map_err(|_| "Invalid discovery helper arguments")?;
        let runtime = &request.snapshot.runtime;
        let service = args.get("service").and_then(Value::as_str);
        let prefix = args.get("prefix").and_then(Value::as_str);
        if name == "services_list" {
            let mut services = runtime.visible_services(&request.identity, &request.context);
            if let Some(selected) = request.view.service() {
                services.retain(|service| service.service == selected);
            }
            return mcp::project_service_list(
                serde_json::to_value(services).map_err(|_| "Cannot encode service discovery")?,
                prefix,
                false,
            )
            .map_err(|_| "Cannot project service discovery");
        }
        let service = service.ok_or("Service is required")?;
        let capabilities = runtime
            .service_capabilities(&request.identity, &request.context, service)
            .ok_or("Service is not visible or does not exist")?;
        match name {
            "services_describe" => {
                serde_json::to_value(capabilities).map_err(|_| "Cannot encode service capabilities")
            }
            "resources_list" => {
                let discovery = runtime
                    .service_discovery(&request.identity, &request.context, service)
                    .ok_or("Service is not visible or does not exist")?;
                let page = discovery.resources(&ResourceListQuery {
                    resource_type: mcp_resource_type(&args)?,
                    prefix: prefix.map(str::to_owned),
                    limit: args
                        .get("limit")
                        .and_then(Value::as_u64)
                        .map(|v| v as usize),
                    cursor: args
                        .get("cursor")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                })?;
                serde_json::to_value(page).map_err(|_| "Cannot encode resource discovery")
            }
            "actions_list" => {
                let discovery = runtime
                    .service_discovery(&request.identity, &request.context, service)
                    .ok_or("Service is not visible or does not exist")?;
                serde_json::to_value(discovery.actions(
                    args.get("resource").and_then(Value::as_str),
                    mcp_resource_type(&args)?.as_ref(),
                    prefix,
                )?)
                .map_err(|_| "Cannot encode action discovery")
            }
            "actions_describe" => {
                let name = args
                    .get("action")
                    .and_then(Value::as_str)
                    .ok_or("Action is required")?;
                let action = capabilities
                    .actions
                    .iter()
                    .find(|a| a.action == name)
                    .ok_or("Action is not visible or does not exist")?;
                let mut detail =
                    serde_json::to_value(action).map_err(|_| "Cannot encode action definition")?;
                if capabilities.surface == "invoke" {
                    let spec = catalog
                        .services
                        .iter()
                        .find(|s| s.service == service)
                        .and_then(|s| s.actions.iter().find(|a| a.action == name))
                        .ok_or("Action detail is unavailable in caller catalog; retry discovery")?;
                    let common: agent_access_core::ActionCapabilities = serde_json::from_value(
                        serde_json::to_value(spec).map_err(|_| "Cannot encode action schema")?,
                    )
                    .map_err(|_| "Invalid action schema")?;
                    if &common != action {
                        return Err("Discovery changed; retry discovery");
                    }
                    detail =
                        serde_json::to_value(spec).map_err(|_| "Cannot encode action schema")?;
                    if let Some(object) = detail.as_object_mut() {
                        object.remove("scopedMcpName");
                    }
                    if let Some(tool) = registry.action_detail(service, name) {
                        detail["mcpTool"] = tool;
                    } else if mcp::action_eligible(spec, ProjectionMode::Http)
                        && let Some(issue) = registry.action_unavailable(service, name)
                    {
                        detail["mcpToolUnavailable"] = json!(issue.code.as_str());
                    }
                }
                detail["service"] = json!(service);
                Ok(detail)
            }
            _ => Err("Unknown discovery helper"),
        }
    }
}
impl ServerHandler for Handler {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![ProtocolVersion::V_2025_11_25])
    }
    fn get_info(&self) -> ServerConfig {
        let mut info=ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(Implementation::new(self.view.service().unwrap_or("agent-access-broker").to_owned(),env!("CARGO_PKG_VERSION"))).with_instructions("Discover Broker services/resources/actions with the five read-only helpers. Only listed native JSON tools execute through this HTTP endpoint. Use local agent-access mcp serve for requestFile, secretSources, multipart uploads and raw downloads. Discovery is not authorization; every call checks current resource grants. Refresh tools/list or reconnect to discover changes. Cancellation and connection loss do not guarantee rollback; never automatically retry uncertain mutations.");
        if let Some(service) = self.view.service() {
            info.instructions = Some(format!(
                "This connection exposes only service {service}. Provider tools use their original names; discovery action IDs remain canonical Broker action IDs. The five helpers require this service when their schema requests service. Only listed JSON tools execute here; file workflows use local agent-access mcp serve --service {service}. Discovery grants no authority; every call checks current policy and credentials. Refresh tools/list after changes. Never automatically retry uncertain mutations."
            ));
        }
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info
    }
    async fn list_tools(
        &self,
        _params: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let request = self.admitted(&context)?;
        *request.delivery_started.lock().unwrap() = Some(Instant::now());
        match request.prepared_discovery.as_deref() {
            Some(PreparedDiscovery::List(result)) => result.clone(),
            _ => Err(ErrorData::internal_error(
                "Missing Broker discovery admission",
                None,
            )),
        }
    }
    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let request = self.admitted(&context)?;
        if let Some(PreparedDiscovery::Helper(result)) = request.prepared_discovery.as_deref() {
            *request.delivery_started.lock().unwrap() = Some(Instant::now());
            return result.clone().map(Into::into);
        }
        let args = params.arguments.unwrap_or_default();
        let limit = request.snapshot.runtime.config().mcp.max_response_bytes;
        let owned = request.clone();
        let name = params.name.clone();
        let (catalog, _registry, target) = tokio::time::timeout(
            Duration::from_millis(request.snapshot.runtime.config().mcp.protocol_timeout_ms),
            tokio::task::spawn_blocking(move || {
                let catalog = Self::catalog(&owned);
                let registry = Self::registry(&owned, &catalog)?;
                let target = registry.resolve(&name).cloned().ok_or_else(|| {
                    ErrorData::invalid_params(
                        "Unknown or unavailable HTTP MCP tool; refresh tools/list and use services_list or services_describe to check availability and setup requirements",
                        None,
                    )
                })?;
                // The HTTP edge uses reserved names only to select a permit pool.
                // The validated registry owns actual dispatch; disagreement fails closed.
                if mcp::is_helper(&name) != matches!(target, ToolTarget::Helper(_)) {
                    return Err(ErrorData::invalid_params(
                        "Unknown or unavailable HTTP MCP tool",
                        None,
                    ));
                }
                Ok::<_, ErrorData>((catalog, registry, target))
            }),
        )
        .await
        .map_err(|_| ErrorData::internal_error("MCP discovery deadline exceeded", None))?
        .map_err(|_| ErrorData::internal_error("MCP discovery failed", None))??;
        if matches!(target, ToolTarget::Helper(_)) {
            return Err(ErrorData::internal_error(
                "Missing Broker discovery admission",
                None,
            ));
        }
        let ToolTarget::Action {
            service,
            action: action_id,
        } = target
        else {
            unreachable!("helper dispatch returned above")
        };
        let action = catalog
            .services
            .iter()
            .find(|item| item.service == service)
            .and_then(|item| {
                item.actions
                    .iter()
                    .find(|action| action.action == action_id)
            })
            .cloned()
            .ok_or_else(|| {
                ErrorData::internal_error("Broker tool registry is inconsistent", None)
            })?;
        if !args.contains_key("inputs")
            || !args["inputs"].is_object()
            || args.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "inputs" | "readContentFormat" | "responseFormat"
                )
            })
        {
            return Ok(output::message("Use inputs and supported presentation options; local file/source arguments require stdio MCP").into());
        }
        for (key, allowed) in [
            ("readContentFormat", &action.read_content_formats),
            ("responseFormat", &action.response_formats),
        ] {
            if let Some(v) = args.get(key)
                && !v.as_str().is_some_and(|s| allowed.iter().any(|a| a == s))
            {
                return Ok(output::message("Unsupported response presentation option").into());
            }
        }
        let invoke: InvokeRequest = match serde_json::from_value(Value::Object(args)) {
            Ok(v) => v,
            Err(_) => return Ok(output::message("Invalid action input wrapper").into()),
        };
        let state = AppState {
            reloadable: self.endpoint.0.state.clone(),
        };
        // Shared ingress can await identity/store work. Bound this phase before
        // registering the operation owner; no provider work has started yet.
        let admission_state = state.clone();
        let admission_request = request.clone();
        let admission_service = service.clone();
        let admission_action = action.action.clone();
        // Identity resolution may use spawn_blocking internally. The admission
        // task owns the response lease until that work actually ends, even if its
        // protocol waiter times out. An abandoned result only drops permits; it
        // cannot register or execute a provider operation.
        let admission_task = tokio::spawn(
            async move {
                let admitted = admit_mcp_invoke(
                    &admission_state,
                    admission_request.snapshot.clone(),
                    admission_request.remote,
                    &admission_request.headers,
                    admission_service,
                    admission_action,
                    &admission_request.identity_pin,
                )
                .await;
                let span = tracing::Span::current();
                if let Err(response) = &admitted {
                    span.record("broker.statusCode", response.status().as_u16());
                }
                span.record("http.statusCode", 200_u16);
                drop(admission_request);
                admitted
            }
            .instrument(request.http_span.clone()),
        );
        let admission = tokio::time::timeout(
            Duration::from_millis(request.snapshot.runtime.config().mcp.protocol_timeout_ms),
            admission_task,
        );
        let admission = tokio::select! {
            biased;
            _ = request.cancellation.cancelled() => {
                *request.delivery_started.lock().unwrap() = Some(Instant::now());
                return Ok(output::message("MCP request canceled before operation admission").into());
            }
            admitted = admission => match admitted {
                Ok(Ok(admitted)) => admitted,
                Ok(Err(_)) => {
                    *request.delivery_started.lock().unwrap() = Some(Instant::now());
                    return Ok(output::message("Broker operation admission failed").into());
                }
                Err(_) => {
                    *request.delivery_started.lock().unwrap() = Some(Instant::now());
                    return Ok(output::message("Broker operation admission deadline exceeded").into());
                }
            }
        };
        let admitted = match admission {
            Ok(a) => a,
            Err(response) => {
                let response = *response;
                let status = response.status();
                let bytes = axum::body::to_bytes(response.into_body(), limit)
                    .await
                    .map_err(|_| ErrorData::internal_error("Broker admission failed", None))?;
                let value=serde_json::from_slice(&bytes).unwrap_or_else(|_|json!({"error":{"message":"Broker admission failed"},"status":status.as_u16()}));
                return Ok(output::admission_failure(value, limit)
                    .unwrap_or_else(|_| output::message("Broker admission failed"))
                    .into());
            }
        };
        let control = InvocationControl::new(Some(Duration::from_millis(
            request.snapshot.runtime.config().mcp.operation_timeout_ms,
        )));
        // Explicit cancellation is authenticated and registered at HTTP ingress,
        // independent of SDK session teardown. Keep that hook alive until the
        // supervised operation's final audit, even when the SDK waiter disappears.
        request.cancellation.attach(control.clone());
        let cancellation = request.cancellation.clone();
        let owner_control = control.clone();
        let owner = tokio::spawn(
            async move {
                let _cancellation = cancellation;
                let response = invoke_admitted_json(&state, admitted, invoke, owner_control).await;
                // Tool failure is carried inside the successful MCP HTTP response.
                // Preserve the canonical outcome separately from its transport.
                let span = tracing::Span::current();
                span.record("broker.statusCode", response.status);
                span.record("http.statusCode", 200_u16);
                response
            }
            .instrument(request.http_span.clone()),
        );
        let response = owner
            .await
            .map_err(|_| ErrorData::internal_error("Broker operation supervisor failed", None))?;
        let result = output::broker(response, &control, limit, &action.sensitive_output_pointers);
        *request.delivery_started.lock().unwrap() = Some(Instant::now());
        Ok(result.into())
    }
}

fn mcp_resource_type(
    args: &Map<String, Value>,
) -> Result<Option<agent_access_core::ResourceType>, &'static str> {
    args.get("resourceType")
        .and_then(Value::as_str)
        .map(|value| {
            agent_access_core::ResourceType::new(value).map_err(|_| "resourceType is invalid")
        })
        .transpose()
}
