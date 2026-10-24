use super::{Admitted, Endpoint, output};
use crate::{
    handlers::data::{admit_mcp_invoke, invoke_admitted_json},
    state::AppState,
};
use agent_access_core::{
    ApiCatalog, DiscoveredService, InvocationControl, InvokeRequest, ResourceAccessQuery,
    mcp::{self, McpView, ProjectionMode, ToolRegistry, ToolTarget},
};
use axum::response::IntoResponse;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, DiscoverResult, Implementation,
        InitializeRequestParams, InitializeResult, ListToolsResult, PaginatedRequestParams,
        ProtocolVersion, ServerCapabilities, ServerConfig, Tool,
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

/// Appended to the server instructions of a read-only identity path.
pub(super) const READ_ONLY_INSTRUCTION: &str =
    "This connection is read-only: only actions classified as reads are listed or executable.";

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
    /// Visibility was resolved in the bounded blocking identity worker. The
    /// HTTP edge adds live state asynchronously before the SDK can dispatch it.
    ServiceDetail(DiscoveredService),
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
    /// Whether the identity admitted for this request uses a read-only path.
    fn read_only_access(&self, context: &RequestContext<RoleServer>) -> Result<bool, ErrorData> {
        Ok(self.admitted(context)?.identity.read_only_access() == Some(true))
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
                let prepare = || -> Result<PreparedDiscovery, ErrorData> {
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
                    let arguments = params.arguments.unwrap_or_default();
                    if *helper == mcp::HelperKind::ServicesDescribe {
                        let detail = || {
                            mcp::validate_helper_arguments_for_view(
                                helper.as_str(),
                                &arguments,
                                ProjectionMode::Http,
                                &request.view,
                            )
                            .map_err(|_| "Invalid discovery helper arguments")?;
                            let service = arguments
                                .get("service")
                                .and_then(Value::as_str)
                                .ok_or("Service is required")?;
                            request
                                .snapshot
                                .runtime
                                .service_capabilities(&request.identity, &request.context, service)
                                .ok_or("Service is not visible or does not exist")
                        };
                        return Ok(match detail() {
                            Ok(service) => PreparedDiscovery::ServiceDetail(service),
                            Err(message) => PreparedDiscovery::Helper(Ok(output::message(message))),
                        });
                    }
                    Ok(PreparedDiscovery::Helper(Ok(match self.helper(request, &catalog, &registry, helper.as_str(), arguments) {
                        Ok(value) => output::result(value, false, limit).unwrap_or_else(|_| output::message(
                            if *helper == mcp::HelperKind::ResourceAccessDescribe {
                                "Resource access result exceeds MCP response limit; use action or resourceType filters, or actions_list for known resources"
                            } else {
                                "Discovery result exceeds MCP response limit; use narrower discovery"
                            },
                        )),
                        Err(message) => output::message(message),
                    })))
                };
                Some(prepare().unwrap_or_else(|error| PreparedDiscovery::Helper(Err(error))))
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
            "resource_access_describe" => {
                let discovery = runtime
                    .service_discovery(&request.identity, &request.context, service)
                    .ok_or("Service is not visible or does not exist")?;
                let page = discovery.resource_access(&ResourceAccessQuery {
                    action: args
                        .get("action")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
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
                serde_json::to_value(page).map_err(|_| "Cannot encode resource access discovery")
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
                    let common: agent_access_provider::ActionCapabilities = serde_json::from_value(
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
        // The assembly names the aggregate server; a scoped server is named
        // after its service. Both report the assembly's version.
        let assembly = &self.endpoint.0.state.build_status;
        let mut info=ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(Implementation::new(self.view.service().unwrap_or(assembly.assembly_name()).to_owned(),assembly.assembly_version())).with_instructions("Discover Broker services/resource access/actions with the five read-only helpers. Only listed native JSON tools execute through this HTTP endpoint. Use local agent-access mcp serve for requestFile, secretSources, multipart uploads and raw downloads. Discovery is not authorization; every call checks current resource grants. Refresh tools/list or reconnect to discover changes. Cancellation and connection loss do not guarantee rollback; never automatically retry uncertain mutations.");
        if let Some(service) = self.view.service() {
            info.instructions = Some(format!(
                "This connection exposes only service {service}. Provider tools use their original names; discovery action IDs remain canonical Broker action IDs. The five helpers require this service when their schema requests service. Only listed JSON tools execute here; file workflows use local agent-access mcp serve --service {service}. Discovery grants no authority; every call checks current policy and credentials. Refresh tools/list after changes. Never automatically retry uncertain mutations."
            ));
        }
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info
    }
    /// The pinned SDK's default `initialize` (store the peer info, negotiate
    /// the protocol version), plus the read-only notice for an admitted
    /// read-only identity path. Changing that setting ends the session, so
    /// the notice holds for the session's lifetime.
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        let read_only = self.read_only_access(&context)?;
        context.peer.set_peer_info(request.clone());
        let mut result = self.negotiate_initialize(&request)?;
        with_read_only_notice(&mut result.instructions, read_only);
        Ok(result)
    }
    /// The pinned SDK's default `discover`, which reports the same server
    /// instructions, with the same read-only notice as `initialize`.
    async fn discover(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, ErrorData> {
        let read_only = self.read_only_access(&context)?;
        let mut result = DiscoverResult::from_server_info(
            self.supported_protocol_versions().into_owned(),
            self.get_info(),
        );
        with_read_only_notice(&mut result.instructions, read_only);
        Ok(result)
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
        // Deliberate rate waiting shares the operation's absolute deadline;
        // the smaller protocol deadline only bounds initial identity work.
        let control = InvocationControl::new(Some(Duration::from_millis(
            request.snapshot.runtime.config().mcp.operation_timeout_ms,
        )));
        request.cancellation.attach(control.clone());
        let receiver_gone = tokio_util::sync::CancellationToken::new();
        let receiver_guard = receiver_gone.clone().drop_guard();
        let lifetime = request
            .lifetime
            .with_operation(
                control
                    .deadline()
                    .expect("MCP operation deadline configured"),
                control.cancellation_token(),
            )
            .with_abandonment(receiver_gone.clone())
            .with_initial_admission_deadline(
                tokio::time::Instant::now()
                    + Duration::from_millis(
                        request.snapshot.runtime.config().mcp.protocol_timeout_ms,
                    ),
            );
        let admission_state = state.clone();
        let waiter_lifetime = lifetime.clone();
        let admission_request = request.clone();
        let admission_service = service.clone();
        let admission_action = action.action.clone();
        let Some(registration) = state.reloadable.admission_owners.register() else {
            *request.delivery_started.lock().unwrap() = Some(Instant::now());
            return Ok(
                output::message("Broker is shutting down before operation admission").into(),
            );
        };
        let (send, mut receive) = tokio::sync::oneshot::channel();
        let (accepted, acknowledgement) = tokio::sync::oneshot::channel();
        // Identity resolution may use spawn_blocking internally. The admission
        // task owns the response lease until that work actually ends, even if its
        // protocol waiter disappears. Its transport token reaches the tracked
        // admission owner; an abandoned result cannot start provider work.
        tokio::spawn(
            async move {
                let _registration = registration;
                let admitted = lifetime
                    .scope(admission_request.renewal.scope(admit_mcp_invoke(
                        &admission_state,
                        admission_request.snapshot.clone(),
                        admission_request.remote,
                        &admission_request.headers,
                        admission_service,
                        admission_action,
                        &admission_request.identity_pin,
                    )))
                    .await;
                let span = tracing::Span::current();
                if let Err(response) = &admitted {
                    span.record("broker.statusCode", response.status().as_u16());
                }
                span.record("http.statusCode", 200_u16);
                match admitted {
                    Ok(admitted) => {
                        if lifetime.cancellation().reason().is_some() {
                            let response = admitted
                                .snapshot
                                .runtime
                                .governed_operation_error_response(
                                    admitted.context,
                                    crate::admission::undispatched_error(
                                        "MCP request abandoned before invocation handoff",
                                    ),
                                )
                                .await;
                            let _ = send.send(Err(Box::new(
                                crate::handlers::common::envelope_response(response)
                                    .into_response(),
                            )));
                        } else {
                            let proof = admitted.context.clone();
                            let snapshot = admitted.snapshot.clone();
                            let _permits = admitted.permits.clone();
                            // A successful send alone does not prove the SDK
                            // waiter took finalization responsibility.
                            if send.send(Ok(admitted)).is_err() || acknowledgement.await.is_err() {
                                snapshot
                                    .runtime
                                    .governed_operation_error_response(
                                        proof,
                                        crate::admission::undispatched_error(
                                            "MCP request abandoned before invocation handoff",
                                        ),
                                    )
                                    .await;
                            }
                        }
                    }
                    Err(response) => {
                        let _ = send.send(Err(response));
                    }
                }
                drop(admission_request);
            }
            .instrument(request.http_span.clone()),
        );
        // Initial identity work can be blocking and must keep its leases even
        // after the protocol deadline. End this timer at the explicit phase
        // boundary; rate waiting has the owner's operation-deadline outcome.
        let initial_result = if let Some(deadline) = waiter_lifetime.initial_admission_deadline() {
            tokio::select! {
                biased;
                result = &mut receive => Some(result),
                () = waiter_lifetime.initial_admission_complete() => None,
                () = tokio::time::sleep_until(deadline) => {
                    if !waiter_lifetime.initial_admission_is_complete() {
                        receiver_gone.cancel();
                        *request.delivery_started.lock().unwrap() = Some(Instant::now());
                        return Ok(output::message("Broker operation admission deadline exceeded").into());
                    }
                    None
                }
            }
        } else {
            None
        };
        // The admission owner produces the sole terminal outcome for queue
        // cancellation/deadline; no separate execution timer races its audit.
        let admission = match match initial_result {
            Some(result) => result,
            None => receive.await,
        } {
            Ok(Ok(admission)) => {
                let _ = accepted.send(());
                Ok(admission)
            }
            Ok(Err(response)) => Err(response),
            Err(_) => {
                *request.delivery_started.lock().unwrap() = Some(Instant::now());
                return Ok(output::message("Broker operation admission failed").into());
            }
        };
        drop(receiver_guard);
        let admitted = match admission {
            Ok(a) => a,
            Err(response) => {
                let response = *response;
                let status = response.status();
                let bytes = axum::body::to_bytes(response.into_body(), limit)
                    .await
                    .map_err(|_| ErrorData::internal_error("Broker admission failed", None))?;
                let value=serde_json::from_slice(&bytes).unwrap_or_else(|_|json!({"error":{"message":"Broker admission failed"},"status":status.as_u16()}));
                *request.delivery_started.lock().unwrap() = Some(Instant::now());
                return Ok(output::admission_failure(value, limit)
                    .unwrap_or_else(|_| output::message("Broker admission failed"))
                    .into());
            }
        };
        // Explicit cancellation is authenticated and registered at HTTP ingress,
        // independent of SDK session teardown. Keep that hook alive until the
        // supervised operation's final audit, even when the SDK waiter disappears.
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

fn with_read_only_notice(instructions: &mut Option<String>, read_only: bool) {
    if read_only && let Some(instructions) = instructions.as_mut() {
        instructions.push(' ');
        instructions.push_str(READ_ONLY_INSTRUCTION);
    }
}

fn mcp_resource_type(
    args: &Map<String, Value>,
) -> Result<Option<agent_access_provider::ResourceType>, &'static str> {
    args.get("resourceType")
        .and_then(Value::as_str)
        .map(|value| {
            agent_access_provider::ResourceType::new(value).map_err(|_| "resourceType is invalid")
        })
        .transpose()
}
