//! Caller-filtered action discovery and local-file adaptation. Authorization stays at the broker.
use agent_access_core::mcp::{
    McpView, ProjectionMode, STDIO_MAX_CATALOG_BYTES, ToolRegistry, ToolTarget,
};
use agent_access_core::{ApiActionSpec, ApiCatalog, InvokeRequest};
use agent_access_provider::{ActionIo, presentation::ResponseOptions};
use anyhow::{Context, Result, bail};
use rmcp::model::{CallToolResult, Tool};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SECRET_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub(super) struct ToolListing {
    pub tools: Vec<Tool>,
    pub binding: Value,
}

pub(super) async fn list_tools(
    settings: &crate::ResolvedCliSettings,
    view: &McpView,
) -> Result<ToolListing> {
    let catalog = fetch_catalog(settings).await?;
    Ok(ToolListing {
        tools: project_catalog(&catalog, view)?,
        binding: json!({"view":view,"identity":catalog.identity,"executionContext":catalog.execution_context}),
    })
}

fn project_catalog(catalog: &ApiCatalog, view: &McpView) -> Result<Vec<Tool>> {
    ToolRegistry::build(
        catalog,
        view,
        ProjectionMode::Stdio,
        STDIO_MAX_CATALOG_BYTES,
    )?
    .definitions()
    .into_iter()
    .map(|definition| {
        serde_json::from_value(definition).context("could not project runtime action")
    })
    .collect()
}

#[cfg(test)]
pub(crate) fn tool_name(service: &str, action: &str) -> String {
    agent_access_core::mcp::tool_name(service, action)
}

pub(crate) fn input_schema(action: &ApiActionSpec) -> Value {
    agent_access_core::mcp::input_schema(action, agent_access_core::mcp::ProjectionMode::Stdio)
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Arguments {
    inputs: Option<Value>,
    request_file: Option<PathBuf>,
    #[serde(default)]
    files: Vec<crate::SendFileDescriptor>,
    output_path: Option<PathBuf>,
    #[serde(default)]
    secret_sources: Vec<crate::SecretSourceBinding>,
    read_content_format: Option<agent_access_provider::presentation::ReadContentFormat>,
    response_format: Option<agent_access_provider::presentation::ResponseFormat>,
}

#[derive(Debug)]
pub(super) struct UnknownToolError;
impl std::fmt::Display for UnknownToolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("tool is not available to the current caller; refresh tools/list and use services_list or services_describe to check availability and setup requirements")
    }
}
impl std::error::Error for UnknownToolError {}

pub(super) async fn call_tool(
    settings: &crate::ResolvedCliSettings,
    view: &McpView,
    name: &str,
    arguments: Map<String, Value>,
) -> Result<CallToolResult> {
    // Aggregate discovery keeps its ordinary broker authorization, including
    // permitted anonymous reads. Fixed helper names are reserved, so resolve
    // them through the same bounded registry generator
    // without requiring the authenticated provider catalog first.
    if matches!(view, McpView::Aggregate) {
        let helpers = ToolRegistry::build(
            &agent_access_core::empty_catalog(json!({})),
            view,
            ProjectionMode::Stdio,
            STDIO_MAX_CATALOG_BYTES,
        )?;
        if let Some(ToolTarget::Helper(helper)) = helpers.resolve(name) {
            return super::discovery::call(settings, view, helper.as_str(), arguments).await;
        }
    }
    let catalog = fetch_catalog(settings).await?;
    let registry = ToolRegistry::build(
        &catalog,
        view,
        ProjectionMode::Stdio,
        STDIO_MAX_CATALOG_BYTES,
    )?;
    let (selected_service, selected_action) =
        match registry.resolve(name).ok_or(UnknownToolError)? {
            ToolTarget::Helper(helper) => {
                return super::discovery::call(settings, view, helper.as_str(), arguments).await;
            }
            ToolTarget::Action { service, action } => (service, action),
        };
    let (service, action) = catalog
        .services
        .iter()
        .find(|service| &service.service == selected_service)
        .and_then(|service| {
            service
                .actions
                .iter()
                .find(|action| &action.action == selected_action)
                .map(|action| (&service.service, action))
        })
        .ok_or(UnknownToolError)?;
    let schema = input_schema(action);
    let supported = schema["properties"]
        .as_object()
        .context("invalid action input schema")?;
    if arguments.keys().any(|key| !supported.contains_key(key)) {
        bail!("argument is not supported by this tool's schema");
    }
    if arguments.contains_key("inputs") == arguments.contains_key("requestFile") {
        bail!("provide exactly one of inputs or requestFile");
    }
    let args: Arguments = serde_json::from_value(Value::Object(arguments))
        .map_err(|_| anyhow::anyhow!("invalid tool arguments"))?;
    if let Some(output) = args.output_path.as_deref() {
        require_absolute(output)?;
    }
    let inputs = {
        let args = args.clone();
        let action = action.clone();
        tokio::task::spawn_blocking(move || resolve_inputs(&args, &action))
            .await
            .context("local input task failed")??
    };
    let options = response_options(settings, &args, action)?;
    let route = format!("/v1/invoke/{service}/{}", action.action);
    let endpoint = crate::endpoint(&settings.url, &route)?;
    let mut reserved = crate::output::ResponseOutput::prepare(
        args.output_path.as_deref(),
        &action.sensitive_output_pointers,
    )?;
    let (status, mut value) = match &action.io {
        ActionIo::Json => {
            if !args.files.is_empty() {
                bail!("this action does not accept files");
            }
            if args.output_path.is_some() && !action.supports_json_file_output() {
                bail!("this action does not accept outputPath");
            }
            let client = mcp_http_client(settings, false)?;
            let response = crate::request_builder(client.post(endpoint), settings)
                .json(&invoke_request(inputs, options))
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("broker request failed"))?;
            decode_json(response, crate::ResponseShape::Envelope).await?
        }
        ActionIo::MultipartUpload { plan } => {
            crate::validate_upload_files(plan, &args.files, service, &action.action)?;
            let (inputs, prepared) = {
                let files = args.files.clone();
                let plan = plan.clone();
                tokio::task::spawn_blocking(move || {
                    let mut inputs = inputs;
                    let prepared = prepare_upload(&files, &plan, &mut inputs)?;
                    Ok::<_, anyhow::Error>((inputs, prepared))
                })
                .await
                .context("local upload task failed")??
            };
            let mut form = reqwest::multipart::Form::new().part(
                "request",
                reqwest::multipart::Part::text(serde_json::to_string(&invoke_request(
                    inputs, options,
                ))?)
                .mime_str("application/json")?,
            );
            for file in &prepared {
                let part = reqwest::multipart::Part::file(file.snapshot.path())
                    .await
                    .context("could not open upload snapshot")?
                    .file_name(file.filename.clone())
                    .mime_str(&file.content_type)
                    .context("invalid upload content type")?;
                form = form.part(file.field.clone(), part);
            }
            let client = mcp_http_client(settings, false)?;
            let response = crate::request_builder(client.post(endpoint), settings)
                .multipart(form)
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("broker upload request failed"))?;
            decode_json(response, crate::ResponseShape::Envelope).await?
        }
        ActionIo::RawDownload {
            metadata_header, ..
        } => {
            if !args.files.is_empty() {
                bail!("downloads do not accept files");
            }
            let output = args
                .output_path
                .as_deref()
                .context("download requires outputPath")?;
            require_absolute(output)?;
            let client = mcp_http_client(settings, true)?;
            let mut response = tokio::time::timeout(
                crate::CLI_REQUEST_TIMEOUT,
                crate::request_builder(client.post(endpoint), settings)
                    .header("Accept", "application/octet-stream")
                    .json(&invoke_request(inputs, options))
                    .send(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("broker download request timed out"))?
            .map_err(|_| anyhow::anyhow!("broker download request failed"))?;
            let status = response.status().as_u16();
            if status >= 400 {
                decode_json(response, crate::ResponseShape::Envelope).await?
            } else {
                let value = crate::parse_download_metadata_header(
                    response
                        .headers()
                        .get(metadata_header)
                        .and_then(|v| v.to_str().ok()),
                )
                .map_err(|_| anyhow::anyhow!("invalid broker download metadata"))?;
                if !crate::response_shape_valid(status, crate::ResponseShape::Envelope, &value) {
                    bail!("invalid broker download envelope");
                }
                if value.get("decision").and_then(Value::as_str) != Some("allow") {
                    bail!("broker download metadata does not authorize a download");
                }
                let content_type = value
                    .pointer("/result/contentType")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        response
                            .headers()
                            .get(reqwest::header::CONTENT_TYPE)
                            .and_then(|value| value.to_str().ok())
                    })
                    .unwrap_or("application/octet-stream")
                    .to_owned();
                let written = crate::write_download_body(&mut response, output, &value, reserved.take().map(crate::output::ResponseOutput::into_file)).await.map_err(|_| anyhow::anyhow!("download failed; destination was not replaced unless final directory synchronization failed"))?;
                let output = crate::output::FileOutput::new(
                    output,
                    written.size,
                    written.sha256,
                    &content_type,
                    !action.sensitive_output_pointers.is_empty(),
                );
                (
                    status,
                    crate::output::receipt(
                        &value,
                        &output,
                        true,
                        &action.sensitive_output_pointers,
                    ),
                )
            }
        }
        _ => bail!("this client does not support the action's input and output kind"),
    };
    let is_error = status >= 400 || value.get("decision").and_then(Value::as_str) != Some("allow");
    let file_receipt = args.output_path.is_some() && !is_error;
    if file_receipt && action.supports_json_file_output() {
        crate::validate_embedded_invoke_result(
            &value,
            options.read_content_format,
            &action.rendered_body_owners,
        )
        .map_err(|_| anyhow::anyhow!("broker response has an invalid rendered body"))?;
        if options.response_format == agent_access_provider::presentation::ResponseFormat::Markdown
        {
            crate::markdown_result_value(&value)
                .map_err(|_| anyhow::anyhow!("broker response has an invalid Markdown result"))?;
        }
        value = reserved
            .take()
            .expect("file output was reserved")
            .save_json(&value)?;
    }
    let mut result = envelope_result(status, value, is_error)?;
    if !file_receipt && !action.sensitive_output_pointers.is_empty() {
        result["_meta"] =
            json!({"agent-access/sensitive-output-pointers":action.sensitive_output_pointers});
    }
    Ok(serde_json::from_value(result)?)
}

/// A tool result with the broker envelope (or file receipt) as structured
/// content. The text repeats it as JSON, except for broker and upstream rate
/// limits: their text is the broker's message, which names the wait, because
/// agents often see only text.
pub(super) fn envelope_result(status: u16, value: Value, is_error: bool) -> Result<Value> {
    let text = match crate::rate_limit_message(status, &value) {
        Some(message) if is_error => message.to_owned(),
        _ => serde_json::to_string(&value)?,
    };
    let content = json!([{"type":"text","text":text}]);
    Ok(json!({"content":content,"structuredContent":value,"isError":is_error}))
}

pub(super) fn save_json_response(path: &Path, value: &Value) -> Result<Value> {
    require_absolute(path)?;
    crate::output::ResponseOutput::prepare(Some(path), &[])
        .map_err(|error| crate::output::LocalOutputFailure::response(value, path, error, &[]))?
        .expect("absolute file path")
        .save_json(value)
}

fn invoke_request(inputs: Value, options: ResponseOptions) -> InvokeRequest {
    InvokeRequest {
        inputs,
        read_content_format: options.read_content_format,
        response_format: options.response_format,
        body_parts: vec![],
    }
}

fn response_options(
    settings: &crate::ResolvedCliSettings,
    args: &Arguments,
    action: &ApiActionSpec,
) -> Result<ResponseOptions> {
    let explicit_read = args.read_content_format.map(|format| match format {
        agent_access_provider::presentation::ReadContentFormat::Native => {
            crate::ReadContentFormatArg::Native
        }
        agent_access_provider::presentation::ReadContentFormat::Markdown => {
            crate::ReadContentFormatArg::Markdown
        }
        agent_access_provider::presentation::ReadContentFormat::Text => {
            crate::ReadContentFormatArg::Text
        }
    });
    let explicit_output = args
        .response_format
        .map(|format| match format {
            agent_access_provider::presentation::ResponseFormat::Json => {
                Ok(crate::OutputFormatArg::Json)
            }
            agent_access_provider::presentation::ResponseFormat::Markdown => {
                Ok(crate::OutputFormatArg::Markdown)
            }
            _ => Err(anyhow::anyhow!(
                "this client does not support the responseFormat"
            )),
        })
        .transpose()?;
    let options = crate::resolve_response_options(
        settings,
        explicit_read,
        explicit_output,
        !action.read_content_formats.is_empty(),
        !action.response_formats.is_empty(),
        &action.action,
    )
    .map_err(|error| {
        // Share CLI precedence and conflict rules, but describe the MCP
        // arguments the caller can actually supply instead of CLI flags.
        anyhow::Error::msg(
            error
                .to_string()
                .replace("--read-content-format", "readContentFormat")
                .replace("--output-format", "responseFormat")
                .replace("read-content format", "readContentFormat")
                .replace("read-content default", "readContentFormat default"),
        )
    })?;
    if options.read_content_format != agent_access_provider::presentation::ReadContentFormat::Native
        && !action
            .read_content_formats
            .iter()
            .any(|format| format == options.read_content_format.as_str())
    {
        bail!("readContentFormat is unsupported for this action");
    }
    if options.response_format != agent_access_provider::presentation::ResponseFormat::Json
        && !action
            .response_formats
            .iter()
            .any(|format| format == options.response_format.as_str())
    {
        bail!("responseFormat is unsupported for this action");
    }
    Ok(options)
}

fn resolve_inputs(args: &Arguments, action: &ApiActionSpec) -> Result<Value> {
    resolve_inputs_with_env(args, action, |name| std::env::var(name))
}

fn resolve_inputs_with_env(
    args: &Arguments,
    action: &ApiActionSpec,
    read_env: impl Fn(&str) -> std::result::Result<String, std::env::VarError>,
) -> Result<Value> {
    let inputs = match (&args.inputs, &args.request_file) {
        (Some(inputs), None) => inputs.clone(),
        (None, Some(path)) => serde_json::from_slice(&read_local_file(path, MAX_JSON_BYTES)?)
            .map_err(|_| anyhow::anyhow!("requestFile must contain valid JSON"))?,
        _ => bail!("provide exactly one of inputs or requestFile"),
    };
    if !inputs.is_object() {
        bail!("action inputs must be a JSON object");
    }
    let mut envelope = json!({"inputs":inputs});
    if args.request_file.is_none() {
        crate::reject_inline_sensitive_values(
            &envelope,
            &action.sensitive_input_pointers,
            &action.secret_input_pointers,
        )?;
    }
    let mut pointers = BTreeSet::new();
    for binding in &args.secret_sources {
        if !crate::sensitive_pointer_allowed(&binding.pointer, &action.sensitive_input_pointers) {
            bail!("secret source pointer is not declared sensitive by the runtime catalog");
        }
        if !pointers.insert(&binding.pointer) {
            bail!("duplicate secret source pointer");
        }
        let secret = match &binding.source {
            crate::LocalSecretSource::Env { name } => {
                let value = read_env(name).map_err(|_| {
                    anyhow::anyhow!("secret source environment variable is not set")
                })?;
                if value.len() as u64 > MAX_SECRET_BYTES {
                    bail!("secret source exceeds 1 MiB limit");
                }
                value
            }
            crate::LocalSecretSource::File { path } => {
                String::from_utf8(read_local_file(path, MAX_SECRET_BYTES)?)
                    .map_err(|_| anyhow::anyhow!("secret source must be UTF-8"))?
            }
            crate::LocalSecretSource::Stdin => {
                bail!("stdin secret sources are unavailable over MCP")
            }
        };
        crate::set_json_pointer(&mut envelope, &binding.pointer, Value::String(secret))?;
    }
    Ok(envelope["inputs"].take())
}

pub(super) fn require_absolute(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("local file paths must be absolute");
    }
    Ok(())
}

fn open_local_file(path: &Path, maximum: u64) -> Result<std::fs::File> {
    require_absolute(path)?;
    // Reject special files before opening (notably FIFOs, which can block indefinitely).
    if !std::fs::metadata(path)
        .context("could not inspect local file")?
        .is_file()
    {
        bail!("local input must be a regular file");
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A path can be replaced after metadata inspection; opening a FIFO must
        // still not block this process indefinitely.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).context("could not open local file")?;
    let metadata = file
        .metadata()
        .context("could not inspect open local file")?;
    if !metadata.is_file() || metadata.len() > maximum {
        bail!("local input is not a regular file within the size limit");
    }
    Ok(file)
}

fn read_local_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = open_local_file(path, maximum)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .context("could not read local file")?;
    if bytes.len() as u64 > maximum {
        bail!("local file exceeds the size limit");
    }
    Ok(bytes)
}

struct PreparedUpload {
    snapshot: tempfile::NamedTempFile,
    field: String,
    filename: String,
    content_type: String,
}

fn prepare_upload(
    files: &[crate::SendFileDescriptor],
    plan: &agent_access_provider::MultipartUploadSpec,
    inputs: &mut Value,
) -> Result<Vec<PreparedUpload>> {
    let mut prepared = Vec::new();
    let mut metadata = Vec::new();
    let mut total = 0;
    for (index, file) in files.iter().enumerate() {
        let source = open_local_file(&file.path, MAX_UPLOAD_BYTES - total)?;
        let mut snapshot =
            tempfile::NamedTempFile::new().context("could not create upload snapshot")?;
        let size = std::io::copy(
            &mut source.take(MAX_UPLOAD_BYTES - total + 1),
            &mut snapshot,
        )
        .context("could not snapshot upload file")?;
        total += size;
        if total > MAX_UPLOAD_BYTES {
            bail!("uploads exceed combined 512 MiB limit");
        }
        snapshot.seek(SeekFrom::Start(0))?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = snapshot.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        snapshot.flush()?;
        let hash = crate::finalize_sha256(digest);
        let filename = file
            .filename
            .clone()
            .or_else(|| {
                file.path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(str::to_owned)
            })
            .context("upload filename must be UTF-8")?;
        let content_type = file.content_type.clone().unwrap_or_else(|| {
            mime_guess::from_path(&file.path)
                .first_or_octet_stream()
                .essence_str()
                .to_owned()
        });
        let field = format!("{}{index}", plan.field_name_prefix);
        metadata.push(crate::upload_metadata_entry(
            plan,
            crate::UploadFileMetadata {
                field: &field,
                filename: &filename,
                content_type: &content_type,
                size,
                sha256: &hash,
            },
            "MCP upload",
        )?);
        prepared.push(PreparedUpload {
            snapshot,
            field,
            filename,
            content_type,
        });
    }
    crate::set_upload_metadata(inputs, plan, metadata)?;
    Ok(prepared)
}

pub(crate) fn mcp_http_client(
    settings: &crate::ResolvedCliSettings,
    streaming: bool,
) -> Result<reqwest::Client> {
    // In particular, never forward a custom identity header to a redirect target.
    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if !streaming {
        builder = builder.timeout(crate::CLI_REQUEST_TIMEOUT);
    }
    crate::build_http_client(builder, &settings.tls)
}

async fn fetch_catalog(settings: &crate::ResolvedCliSettings) -> Result<ApiCatalog> {
    let client = mcp_http_client(settings, false)?;
    let response = crate::request_builder(
        client.get(crate::endpoint(&settings.url, "/v1/spec/catalog")?),
        settings,
    )
    .send()
    .await
    .map_err(|_| anyhow::anyhow!("broker catalog request failed"))?;
    let (status, value) = decode_json(response, crate::ResponseShape::Object).await?;
    if status >= 400 {
        bail!("broker catalog request rejected (HTTP {status})");
    }
    if value.get("version").and_then(Value::as_str) != Some(agent_access_core::API_CATALOG_VERSION)
    {
        bail!("unsupported broker catalog version");
    }
    serde_json::from_value(value).map_err(|_| anyhow::anyhow!("invalid broker catalog"))
}

pub(crate) async fn decode_json(
    mut response: reqwest::Response,
    shape: crate::ResponseShape,
) -> Result<(u16, Value)> {
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        bail!("broker redirects are not supported");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) =
        tokio::time::timeout(crate::CLI_STREAMING_IDLE_TIMEOUT, response.chunk())
            .await
            .map_err(|_| anyhow::anyhow!("broker response stalled"))?
            .map_err(|_| anyhow::anyhow!("could not read broker response"))?
    {
        if (bytes.len() + chunk.len()) as u64 > MAX_JSON_BYTES {
            bail!("broker JSON response exceeds 16 MiB limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    let value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("broker response is not valid JSON"))?;
    if !crate::response_shape_valid(status, shape, &value) {
        bail!("broker response has an invalid shape");
    }
    Ok((status, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    fn action() -> ApiActionSpec {
        serde_json::from_value(json!({
            "action":"issue.view","scopedMcpName":"issue.view","description":"Read an issue","readOnly":true,"requiredScopeTypes":[],"credentialModes":[],
            "inputSchema":{"type":"object","required":["issue"],"properties":{"issue":{"type":"string"}}},
            "io":{"type":"json"},"responseKind":"response_envelope","exitPolicy":"invoke_decision"
        })).unwrap()
    }
    fn catalog(action: ApiActionSpec) -> ApiCatalog {
        let mut catalog = agent_access_core::empty_catalog(json!({}));
        catalog.services.push(agent_access_core::ApiServiceSpec {
            availability: Some(agent_access_core::ServiceAvailability {
                state: agent_access_core::AvailabilityState::Available,
                requirements: vec![],
                message: "Locally available".into(),
            }),
            service: "jira-team".into(),
            display_name: "Team Jira".into(),
            surface: "invoke".into(),
            scoped_mcp_ready: true,
            scope_types: vec![],
            resource_scopes: Default::default(),
            actions: vec![action],
        });
        catalog
    }
    fn settings(server: &MockServer) -> crate::ResolvedCliSettings {
        crate::ResolvedCliSettings {
            url: server.uri(),
            tls: Default::default(),
            token: Some("broker-secret".into()),
            token_from_literal_arg: false,
            identity_header: "X-Agent-Access-Identity-Token".into(),
            identity_scheme: "raw".into(),
            allow_insecure_broker_http: false,
            read_content_format: Default::default(),
            output_format: Default::default(),
        }
    }
    fn args(value: Value) -> Arguments {
        serde_json::from_value(value).unwrap()
    }
    async fn serve_catalog(server: &MockServer, action: ApiActionSpec) {
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .and(header("X-Agent-Access-Identity-Token", "broker-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(catalog(action)))
            .mount(server)
            .await;
    }
    fn allow(result: Value) -> Value {
        json!({"agentRequestId":"agent","brokerRequestId":"broker","decision":"allow","result":result})
    }

    #[tokio::test]
    async fn presentation_options_preserve_cli_default_and_conflict_rules() {
        let server = MockServer::start().await;
        let mut settings = settings(&server);
        settings.read_content_format = agent_access_provider::presentation::ReadContentFormat::Text;
        let mut action = action();
        action.read_content_formats = vec!["native".into(), "markdown".into(), "text".into()];
        action.response_formats = vec!["json".into(), "markdown".into()];
        let selected = response_options(
            &settings,
            &args(json!({"inputs":{}, "responseFormat":"markdown"})),
            &action,
        )
        .unwrap();
        assert_eq!(
            selected.read_content_format,
            agent_access_provider::presentation::ReadContentFormat::Native
        );
        assert_eq!(
            selected.response_format,
            agent_access_provider::presentation::ResponseFormat::Markdown
        );
        let explicit_error = response_options(
            &settings,
            &args(json!({"inputs":{}, "responseFormat":"markdown", "readContentFormat":"text"})),
            &action,
        )
        .unwrap_err()
        .to_string();
        assert!(explicit_error.contains("responseFormat"));
        assert!(explicit_error.contains("readContentFormat"));
        assert!(!explicit_error.contains("--"), "{explicit_error}");
        settings.output_format = agent_access_provider::presentation::ResponseFormat::Markdown;
        let ambient_error = response_options(&settings, &args(json!({"inputs":{}})), &action)
            .unwrap_err()
            .to_string();
        assert!(ambient_error.contains("responseFormat markdown"));
        assert!(ambient_error.contains("readContentFormat default"));
        assert!(!ambient_error.contains("--"), "{ambient_error}");
        action.read_content_formats.clear();
        action.response_formats.clear();
        assert_eq!(
            response_options(&settings, &args(json!({"inputs":{}})), &action).unwrap(),
            ResponseOptions::default()
        );
    }

    fn gitlab_action(name: &str) -> ApiActionSpec {
        let config = serde_json::from_value(json!({
            "api_base_url":"https://gitlab.example.com/api/v4",
            "web_base_url":"https://gitlab.example.com",
            "allowed_upstream_hosts":["https://gitlab.example.com/api/v4/**"]
        }))
        .unwrap();
        agent_access_core::api_service_spec(
            &agent_access_gitlab::gitlab_descriptor(&config),
            true,
            agent_access_core::SecretOutputMode::Reference,
        )
        .unwrap()
        .actions
        .into_iter()
        .find(|action| action.action == name)
        .unwrap()
    }

    #[test]
    fn real_webhook_schema_accepts_secret_only_updates_without_losing_resource_requirements() {
        let action = gitlab_action("webhook.update");
        let original = jsonschema::validator_for(&action.input_schema).unwrap();
        let projected = jsonschema::validator_for(&input_schema(&action)).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let secret_file = temp.path().join("secret");
        for (field, secret) in [
            ("token", "webhook-secret".to_owned()),
            ("signingToken", format!("whsec_{}=", "A".repeat(43))),
        ] {
            std::fs::write(&secret_file, secret).unwrap();
            let request = json!({
                "inputs":{"project":"team/project","webhookId":7},
                "secretSources":[{"pointer":format!("/inputs/{field}"),"source":{"type":"file","path":secret_file}}]
            });
            assert!(
                !original.is_valid(&request["inputs"]),
                "fixture must require an actual mutation"
            );
            assert!(
                projected.is_valid(&request),
                "secret-only {field} update is valid before injection"
            );
            let inputs = resolve_inputs(&args(request.clone()), &action).unwrap();
            assert!(
                original.is_valid(&inputs),
                "injected {field} update satisfies the actual provider schema"
            );
            for resource_field in ["project", "webhookId"] {
                let mut missing = request.clone();
                missing["inputs"]
                    .as_object_mut()
                    .unwrap()
                    .remove(resource_field);
                assert!(
                    !projected.is_valid(&missing),
                    "must retain required {resource_field}"
                );
            }
        }
        assert!(projected.is_valid(
            &json!({"inputs":{"project":"team/project","webhookId":7,"name":"renamed"}})
        ));
        assert!(!projected.is_valid(
            &json!({"inputs":{"project":"team/project","webhookId":7,"events":["unknown_event"]}})
        ));
        assert!(!projected.is_valid(&json!({"inputs":{"project":"team/project","webhookId":7,"token":"inline","clearToken":true}})), "negative token/clearToken exclusivity stays intact");
    }

    #[test]
    fn names_are_readable_and_keep_the_full_canonical_spelling() {
        let first = tool_name("jira-team", "issue.view");
        assert_eq!(first, "jira_team_issue_view");
        assert_eq!(first, tool_name("jira_team", "issue.view"));
        assert_eq!(first, tool_name("jira-team", "issue_view"));
        let long = tool_name(&"a".repeat(100), &"b".repeat(100));
        assert_eq!(long.len(), 201);
        assert!(
            long.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        );
    }

    #[test]
    fn projection_filters_surfaces_and_retains_searchable_schema_and_secret_markers() {
        let mut action = action();
        action.sensitive_output_pointers = vec!["/result/issuedToken".into()];
        action.input_schema["$defs"] = json!({"Issue":{"type":"string"}});
        action.input_schema["properties"]["issue"] = json!({"$ref":"#/$defs/Issue"});
        let mut catalog = catalog(action);
        let mut hidden = catalog.services[0].clone();
        hidden.surface = "gateway".into();
        catalog.services.push(hidden);
        let tools = project_catalog(&catalog, &McpView::Aggregate).unwrap();
        assert_eq!(tools.len(), 6);
        let tool = serde_json::to_value(
            tools
                .iter()
                .find(|tool| tool.name == tool_name("jira-team", "issue.view"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            tool["inputSchema"]["properties"]["inputs"]["properties"]["issue"]["$ref"],
            "#/properties/inputs/$defs/Issue"
        );
        assert_eq!(
            tool["_meta"]["agent-access/sensitive-output-pointers"][0],
            "/result/issuedToken"
        );
        assert!(
            tool["description"]
                .as_str()
                .unwrap()
                .contains("jira-team.issue.view")
        );
        assert!(
            tool["inputSchema"]["properties"]
                .get("outputPath")
                .is_some()
        );
        catalog.services.push(catalog.services[0].clone());
        assert!(project_catalog(&catalog, &McpView::Aggregate).is_err());
    }

    #[test]
    fn actual_upload_schema_advertises_locators_and_files_without_generated_metadata() {
        let action = gitlab_action("project.upload");
        assert!(
            action.input_schema["properties"]
                .get("attachments")
                .is_some()
        );
        let schema = input_schema(&action);
        assert!(
            schema["properties"]["inputs"]["properties"]
                .get("attachments")
                .is_none()
        );
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&json!({
            "inputs":{"project":"team/project"},
            "files":[{"role":"attachment","path":"/tmp/report.txt"}]
        })));
        assert!(
            !validator.is_valid(&json!({
                "inputs":{"project":"team/project","attachments":[]},
                "files":[{"role":"attachment","path":"/tmp/report.txt"}]
            })),
            "generated metadata is not a caller input"
        );
        assert!(
            !validator.is_valid(&json!({"inputs":{"project":"team/project"}})),
            "local files are still required"
        );
    }

    #[test]
    fn environment_secret_sources_resolve_and_fail_closed_with_bounded_values() {
        let mut action = action();
        action.sensitive_input_pointers = vec!["/inputs/token".into()];
        let arguments = args(json!({"inputs":{},"secretSources":[{
            "pointer":"/inputs/token","source":{"type":"env","name":"MCP_TEST_SECRET"}
        }]}));
        let resolved = resolve_inputs_with_env(&arguments, &action, |name| {
            assert_eq!(name, "MCP_TEST_SECRET");
            Ok("environment-secret".into())
        })
        .unwrap();
        assert_eq!(resolved["token"], "environment-secret");
        let missing =
            resolve_inputs_with_env(&arguments, &action, |_| Err(std::env::VarError::NotPresent))
                .unwrap_err();
        assert_eq!(
            missing.to_string(),
            "secret source environment variable is not set"
        );
        let at_limit = resolve_inputs_with_env(&arguments, &action, |_| {
            Ok("x".repeat(MAX_SECRET_BYTES as usize))
        })
        .unwrap();
        assert_eq!(
            at_limit["token"].as_str().unwrap().len(),
            MAX_SECRET_BYTES as usize
        );
        let oversized = resolve_inputs_with_env(&arguments, &action, |_| {
            Ok("x".repeat(MAX_SECRET_BYTES as usize + 1))
        })
        .unwrap_err();
        assert_eq!(oversized.to_string(), "secret source exceeds 1 MiB limit");
    }

    #[test]
    fn files_are_bounded_and_input_modes_exclusive() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("request.json");
        std::fs::write(&file, br#"{"issue":"ABC-1"}"#).unwrap();
        assert_eq!(
            resolve_inputs(&args(json!({"requestFile":file})), &action()).unwrap()["issue"],
            "ABC-1"
        );
        assert!(read_local_file(&file, 2).is_err());
        assert!(read_local_file(temp.path(), 100).is_err());
        assert!(read_local_file(Path::new("relative.json"), 100).is_err());
        assert!(resolve_inputs(&args(json!({"inputs":{},"requestFile":file})), &action()).is_err());
        assert!(resolve_inputs(&args(json!({"inputs":null})), &action()).is_err());
    }

    #[test]
    fn declared_secret_inputs_accept_inline_references_but_keep_literal_sources_private() {
        let mut action = action();
        action.sensitive_input_pointers = vec!["/inputs/token".into()];
        action.secret_input_pointers = vec!["/inputs/token".into()];
        let reference = json!({
            "secretRef":format!("sr_{}", "A".repeat(43)),
            "expiresAt":"2099-01-01T00:00:00Z",
        });
        let arguments = args(json!({"inputs":{"token":reference}}));
        assert_eq!(
            resolve_inputs(&arguments, &action).unwrap()["token"],
            reference
        );
        for inputs in [
            json!({"token":"inline-secret"}),
            json!({"token":format!("sr_{}", "A".repeat(43))}),
            json!({"other":reference}),
            json!({"token":{"secretRef":reference["secretRef"],"extra":"literal"}}),
        ] {
            assert!(resolve_inputs(&args(json!({"inputs":inputs})), &action).is_err());
        }
        action.secret_input_pointers.clear();
        assert!(resolve_inputs(&arguments, &action).is_err());

        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("request.json");
        std::fs::write(&file, br#"{"token":"local-literal-secret"}"#).unwrap();
        assert_eq!(
            resolve_inputs(&args(json!({"requestFile":file})), &action).unwrap()["token"],
            "local-literal-secret"
        );
    }

    #[test]
    fn sensitive_values_require_local_sources_and_stdin_is_rejected() {
        let mut action = action();
        action.sensitive_input_pointers = vec!["/inputs/token".into()];
        assert!(resolve_inputs(&args(json!({"inputs":{"token":"secret"}})), &action).is_err());
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("secret");
        std::fs::write(&file, "local-secret").unwrap();
        let source = json!({"pointer":"/inputs/token","source":{"type":"file","path":file}});
        assert_eq!(
            resolve_inputs(
                &args(json!({"inputs":{},"secretSources":[source.clone()]})),
                &action
            )
            .unwrap()["token"],
            "local-secret"
        );
        assert!(
            resolve_inputs(
                &args(json!({"inputs":{},"secretSources":[source.clone(),source]})),
                &action
            )
            .is_err()
        );
        assert!(resolve_inputs(&args(json!({"inputs":{},"secretSources":[{"pointer":"/inputs/token","source":{"type":"stdin"}}]})),&action).is_err());
        assert!(resolve_inputs(&args(json!({"inputs":{},"secretSources":[{"pointer":"/inputs/other","source":{"type":"file","path":file}}]})),&action).is_err());
    }

    #[tokio::test]
    async fn catalog_version_is_checked_before_the_current_shape() {
        let server = MockServer::start().await;
        for version in [
            "agent-access.catalog.v1",
            agent_access_core::API_CATALOG_VERSION,
        ] {
            for missing_action_name in [false, true] {
                server.reset().await;
                let mut value = serde_json::to_value(catalog(action())).unwrap();
                value["version"] = json!(version);
                if missing_action_name {
                    value["services"][0]["actions"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("scopedMcpName");
                } else {
                    value["services"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("scopedMcpReady");
                }
                Mock::given(method("GET"))
                    .and(path("/v1/spec/catalog"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(value))
                    .mount(&server)
                    .await;
                let error = fetch_catalog(&settings(&server)).await.unwrap_err();
                assert_eq!(
                    error.to_string(),
                    if version == agent_access_core::API_CATALOG_VERSION {
                        "invalid broker catalog"
                    } else {
                        "unsupported broker catalog version"
                    }
                );
            }
        }
    }

    #[tokio::test]
    async fn invalid_registry_rejects_provider_dispatch_before_local_files() {
        let server = MockServer::start().await;
        let mut value = catalog(action());
        value.services.push(value.services[0].clone());
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(value))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/services"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .expect(0)
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("result.json");
        std::fs::write(&output, "preserve").unwrap();
        let error = call_tool(
            &settings(&server),
            &McpView::Aggregate,
            &tool_name("jira-team", "issue.view"),
            json!({"requestFile": directory.path().join("does-not-exist"), "outputPath":output})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "runtime catalog has duplicate action identities"
        );
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "preserve");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        server.verify().await;
    }

    #[tokio::test]
    async fn aggregate_anonymous_helper_uses_ordinary_discovery_without_catalog_probe() {
        let server = MockServer::start().await;
        let denial = json!({"agentRequestId":"a","brokerRequestId":"b","decision":"deny","reasonCode":"identity_required"});
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(401).set_body_json(denial.clone()))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/services"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .expect(1)
            .mount(&server)
            .await;
        let mut anonymous = settings(&server);
        anonymous.token = None;
        let result = call_tool(&anonymous, &McpView::Aggregate, "services_list", Map::new())
            .await
            .unwrap();
        let result = serde_json::to_value(result).unwrap();
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"], json!({"services":[]}));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0]
                .headers
                .contains_key("X-Agent-Access-Identity-Token")
        );
        server.verify().await;
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(401).set_body_json(denial))
            .expect(2)
            .mount(&server)
            .await;
        for name in ["unknown".to_owned(), tool_name("jira-team", "issue.view")] {
            let error = call_tool(&anonymous, &McpView::Aggregate, &name, Map::new())
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "broker catalog request rejected (HTTP 401)"
            );
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn scoped_registry_routes_identical_raw_names_and_rejects_other_names_before_local_io() {
        let server = MockServer::start().await;
        let mut value = catalog(action());
        value.services[0].actions[0].scoped_mcp_name = Some("OriginalRead".into());
        let mut second = value.services[0].clone();
        second.service = "second".into();
        let mut other = action();
        other.action = "other.only".into();
        other.scoped_mcp_name = Some("OtherOnly".into());
        second.actions.push(other);
        value.services.push(second);
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(value.clone()))
            .mount(&server)
            .await;
        for service in ["jira-team", "second"] {
            Mock::given(method("POST"))
                .and(path(format!("/v1/invoke/{service}/issue.view")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(allow(json!({"service":service}))),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        for service in ["jira-team", "second"] {
            let result = call_tool(
                &settings(&server),
                &McpView::Service(service.into()),
                "OriginalRead",
                json!({"inputs":{"issue":"ABC-1"}})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .await
            .unwrap();
            assert_eq!(
                serde_json::to_value(result).unwrap()["structuredContent"]["result"]["service"],
                service
            );
        }
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("existing.json");
        std::fs::write(&output, "preserve").unwrap();
        for name in [
            "OtherOnly".to_owned(),
            tool_name("jira-team", "issue.view"),
            "unknown".into(),
        ] {
            let error = call_tool(
                &settings(&server),
                &McpView::Service("jira-team".into()),
                &name,
                json!({"requestFile":directory.path().join("missing"),"outputPath":output})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .await
            .unwrap_err();
            assert!(error.is::<UnknownToolError>());
        }
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "preserve");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        server.verify().await;
    }

    #[tokio::test]
    async fn scoped_helpers_restrict_forwarding_and_saved_results_and_require_readiness() {
        let server = MockServer::start().await;
        let mut value = catalog(action());
        let mut second = value.services[0].clone();
        second.service = "second".into();
        value.services.push(second);
        let current = std::sync::Arc::new(std::sync::Mutex::new(value.clone()));
        let respond = current.clone();
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(respond.lock().unwrap().clone())
            })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/services"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(value.services)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/services/second/resources"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let view = McpView::Service("jira-team".into());
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("result.json");
        let result = call_tool(
            &settings(&server),
            &view,
            "services_list",
            json!({"outputPath":output}).as_object().unwrap().clone(),
        )
        .await
        .unwrap();
        assert_eq!(serde_json::to_value(result).unwrap()["isError"], false);
        let saved: Value = serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
        assert_eq!(saved["services"].as_array().unwrap().len(), 1);
        assert_eq!(saved["services"][0]["service"], "jira-team");
        let bytes = std::fs::read(&output).unwrap();
        let error = call_tool(
            &settings(&server),
            &view,
            "resources_list",
            json!({"service":"second","outputPath":output})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "service is outside this MCP view");
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
        for unavailable in [McpView::Service("missing".into()), view.clone()] {
            current.lock().unwrap().services[0].scoped_mcp_ready = false;
            let error = call_tool(
                &settings(&server),
                &unavailable,
                "services_list",
                json!({"outputPath":output}).as_object().unwrap().clone(),
            )
            .await
            .unwrap_err();
            assert_eq!(error.to_string(), "service view is unavailable");
            assert_eq!(std::fs::read(&output).unwrap(), bytes);
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn scoped_action_detail_rebuilds_name_and_schema_from_one_fresh_catalog() {
        let server = MockServer::start().await;
        let mut initial = catalog(action());
        initial.services[0].actions[0].scoped_mcp_name = Some("InitialName".into());
        let mut fresh = initial.clone();
        fresh.services[0].actions[0].scoped_mcp_name = Some("CurrentName".into());
        fresh.services[0].actions[0].input_schema =
            json!({"type":"object","properties":{"newField":{"type":"boolean"}}});
        let sequence = std::sync::atomic::AtomicUsize::new(0);
        let current = fresh.clone();
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(
                    if sequence.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                        &initial
                    } else {
                        &current
                    },
                )
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/services/jira-team"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&fresh.services[0]))
            .expect(1)
            .mount(&server)
            .await;
        let result = call_tool(
            &settings(&server),
            &McpView::Service("jira-team".into()),
            "actions_describe",
            json!({"service":"jira-team","action":"issue.view"})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .unwrap();
        let result = serde_json::to_value(result).unwrap();
        let detail = &result["structuredContent"];
        assert_eq!(detail["mcpTool"]["name"], "CurrentName");
        assert_eq!(
            detail["inputSchema"],
            fresh.services[0].actions[0].input_schema
        );
        assert_eq!(
            detail["mcpTool"]["inputSchema"]["properties"]["inputs"],
            detail["inputSchema"]
        );
        assert!(detail.get("scopedMcpName").is_none());
        server.verify().await;
    }

    #[tokio::test]
    async fn small_selected_view_still_obeys_whole_catalog_decode_limit() {
        let server = MockServer::start().await;
        let mut value = catalog(action());
        let mut unrelated = value.services[0].clone();
        unrelated.service = "unrelated".into();
        unrelated.actions[0].description = "x".repeat(MAX_JSON_BYTES as usize);
        value.services.push(unrelated);
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(value))
            .mount(&server)
            .await;
        let error = list_tools(&settings(&server), &McpView::Service("jira-team".into()))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "broker JSON response exceeds 16 MiB limit"
        );
    }

    #[tokio::test]
    async fn fresh_catalog_and_json_invocation_share_identity_and_preserve_denials() {
        let server = MockServer::start().await;
        serve_catalog(&server, action()).await;
        let body =
            json!({"agentRequestId":"a","brokerRequestId":"b","decision":"deny","result":null});
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira-team/issue.view"))
            .and(header("X-Agent-Access-Identity-Token", "broker-secret"))
            .and(body_json(json!({"inputs":{"issue":"ABC-1"},"readContentFormat":"native","responseFormat":"json"})))
            .respond_with(ResponseTemplate::new(403).set_body_json(body.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let result = call_tool(
            &settings(&server),
            &McpView::Aggregate,
            &tool_name("jira-team", "issue.view"),
            json!({"inputs":{"issue":"ABC-1"}})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .unwrap();
        let result = serde_json::to_value(result).unwrap();
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"], body);
        let missing = call_tool(
            &settings(&server),
            &McpView::Aggregate,
            "unknown",
            Map::new(),
        )
        .await
        .unwrap_err();
        assert!(missing.downcast_ref::<UnknownToolError>().is_some());
    }

    #[tokio::test]
    async fn json_file_output_saves_complete_envelope_and_returns_only_receipt() {
        let server = MockServer::start().await;
        let mut action = action();
        action.read_only = false;
        action.sensitive_output_pointers = vec!["/result/private".into()];
        serve_catalog(&server, action).await;
        let body = allow(json!({"private":"sensitive-body","items":[1,2],"nextCursor":"next"}));
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira-team/issue.view"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("response.json");
        std::fs::write(&destination, "old response").unwrap();
        let result = call_tool(
            &settings(&server),
            &McpView::Aggregate,
            &tool_name("jira-team", "issue.view"),
            json!({"inputs":{"issue":"ABC-1"},"outputPath":destination})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .unwrap();
        let result = serde_json::to_value(result).unwrap();
        let bytes = std::fs::read(&destination).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), body);
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["brokerRequestId"], "broker");
        assert_eq!(result["structuredContent"]["output"]["size"], bytes.len());
        assert_eq!(
            result["structuredContent"]["output"]["sha256"],
            format!("{:x}", Sha256::digest(&bytes))
        );
        assert_eq!(result["structuredContent"]["output"]["sensitive"], true);
        assert_eq!(
            result["structuredContent"]["output"]["contentType"],
            "application/json"
        );
        assert!(result["structuredContent"].get("result").is_none());
        assert!(result.get("_meta").is_none());
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("sensitive-body")
        );
    }

    #[tokio::test]
    async fn mutation_file_output_failure_retains_success_identifiers_and_invokes_once() {
        let server = MockServer::start().await;
        let mut action = action();
        action.read_only = false;
        action.sensitive_output_pointers = vec!["/result/secret".into()];
        serve_catalog(&server, action).await;
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("response.json");
        let race_destination = destination.clone();
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira-team/issue.view"))
            .respond_with(move |_: &wiremock::Request| {
                std::fs::create_dir(&race_destination).unwrap();
                ResponseTemplate::new(200).set_body_json(allow(json!({"secret":"not-retained"})))
            })
            .expect(1)
            .mount(&server)
            .await;
        let error = call_tool(
            &settings(&server),
            &McpView::Aggregate,
            &tool_name("jira-team", "issue.view"),
            json!({"inputs":{"issue":"ABC-1"},"outputPath":destination})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .unwrap_err();
        let failure = error
            .downcast_ref::<crate::output::LocalOutputFailure>()
            .unwrap();
        assert_eq!(failure.details["operationStatus"], "succeeded");
        assert_eq!(failure.details["output"]["status"], "failed");
        assert_eq!(failure.details["agentRequestId"], "agent");
        assert_eq!(failure.details["brokerRequestId"], "broker");
        assert!(!failure.to_string().contains("not-retained"));
        server.verify().await;
    }

    #[tokio::test]
    async fn unverified_mutation_outcome_survives_mcp_file_success_and_failure() {
        for save_fails in [false, true] {
            let server = MockServer::start().await;
            let mut action = action();
            action.read_only = false;
            action.sensitive_output_pointers = vec!["/result/secret".into()];
            serve_catalog(&server, action).await;
            let directory = tempfile::tempdir().unwrap();
            let destination = directory.path().join("output.json");
            let race_destination = destination.clone();
            Mock::given(method("POST")).and(path("/v1/invoke/jira-team/issue.view"))
                .respond_with(move |_: &wiremock::Request| {
                    if save_fails { std::fs::create_dir(&race_destination).unwrap(); }
                    ResponseTemplate::new(200).set_body_json(allow(json!({"mutationStatus":"applied_unverified","retrySafe":false,"verificationStage":"mutation_response","safeLocators":{"job":"ci/build"},"secret":"not-retained"})))
                }).expect(1).mount(&server).await;
            let result = call_tool(
                &settings(&server),
                &McpView::Aggregate,
                &tool_name("jira-team", "issue.view"),
                json!({"inputs":{"issue":"ABC-1"},"outputPath":destination})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .await;
            let receipt = if save_fails {
                result
                    .unwrap_err()
                    .downcast_ref::<crate::output::LocalOutputFailure>()
                    .unwrap()
                    .details
                    .clone()
            } else {
                serde_json::to_value(result.unwrap()).unwrap()["structuredContent"].clone()
            };
            assert_eq!(receipt["operationStatus"], "applied_unverified");
            assert_eq!(receipt["mutationStatus"], "applied_unverified");
            assert_eq!(receipt["retrySafe"], false);
            assert_eq!(receipt["safeLocators"]["job"], "ci/build");
            assert!(!receipt.to_string().contains("not-retained"));
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn invalid_mcp_response_and_download_paths_prevent_dispatch() {
        for raw in [false, true] {
            for directory_path in [false, true] {
                let server = MockServer::start().await;
                let mut action = action();
                action.read_only = raw;
                action.sensitive_output_pointers = vec!["/result/issuedToken".into()];
                if raw {
                    action.io = agent_access_provider::raw_download_io();
                }
                serve_catalog(&server, action).await;
                Mock::given(method("POST"))
                    .respond_with(ResponseTemplate::new(500))
                    .expect(0)
                    .mount(&server)
                    .await;
                let directory = tempfile::tempdir().unwrap();
                let destination = if directory_path {
                    directory.path().join("directory")
                } else {
                    directory.path().join("missing/output")
                };
                if directory_path {
                    std::fs::create_dir(&destination).unwrap();
                }
                let before = std::fs::read_dir(directory.path()).unwrap().count();
                let error = call_tool(
                    &settings(&server),
                    &McpView::Aggregate,
                    &tool_name("jira-team", "issue.view"),
                    json!({"inputs":{"issue":"ABC-1"},"outputPath":destination})
                        .as_object()
                        .unwrap()
                        .clone(),
                )
                .await
                .unwrap_err();
                assert!(!error.is::<crate::output::LocalOutputFailure>());
                assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), before);
                server.verify().await;
            }
        }
    }

    #[tokio::test]
    async fn json_file_output_preserves_destination_on_denied_and_malformed_responses() {
        for (status, body) in [
            (
                403,
                json!({"agentRequestId":"a","brokerRequestId":"b","decision":"deny","result":null}),
            ),
            (200, json!({"unexpected":"response"})),
        ] {
            let server = MockServer::start().await;
            serve_catalog(&server, action()).await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status).set_body_json(body.clone()))
                .mount(&server)
                .await;
            let temp = tempfile::tempdir().unwrap();
            let destination = temp.path().join("response.json");
            std::fs::write(&destination, "original").unwrap();
            let result = call_tool(
                &settings(&server),
                &McpView::Aggregate,
                &tool_name("jira-team", "issue.view"),
                json!({"inputs":{"issue":"ABC-1"},"outputPath":destination})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .await;
            if status == 403 {
                let result = serde_json::to_value(result.unwrap()).unwrap();
                assert_eq!(result["isError"], true);
                assert_eq!(result["structuredContent"], body);
            } else {
                assert!(result.is_err());
            }
            assert_eq!(std::fs::read_to_string(destination).unwrap(), "original");
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        }
    }

    #[tokio::test]
    async fn markdown_file_output_keeps_json_envelope_and_rejects_invalid_wrapper() {
        for formatted in [
            json!({"format":"markdown","value":"# Issue\nDetails\n"}),
            json!({"format":"markdown","value":42}),
        ] {
            let server = MockServer::start().await;
            let mut action = action();
            action.response_formats = vec!["json".into(), "markdown".into()];
            serve_catalog(&server, action).await;
            let body = allow(formatted.clone());
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
                .mount(&server)
                .await;
            let temp = tempfile::tempdir().unwrap();
            let destination = temp.path().join("formatted.json");
            std::fs::write(&destination, "original").unwrap();
            let result = call_tool(&settings(&server), &McpView::Aggregate, &tool_name("jira-team", "issue.view"),
                json!({"inputs":{"issue":"ABC-1"},"responseFormat":"markdown","outputPath":destination}).as_object().unwrap().clone()).await;
            if formatted["value"].is_string() {
                let result = serde_json::to_value(result.unwrap()).unwrap();
                assert_eq!(
                    result["structuredContent"]["output"]["contentType"],
                    "application/json"
                );
                assert_eq!(
                    serde_json::from_slice::<Value>(&std::fs::read(destination).unwrap()).unwrap(),
                    body
                );
            } else {
                assert!(result.is_err());
                assert_eq!(std::fs::read_to_string(destination).unwrap(), "original");
            }
        }
    }

    #[tokio::test]
    async fn json_output_rejects_relative_paths_before_invocation() {
        for (read_only, output) in [(true, "relative.json"), (false, "relative-write.json")] {
            let server = MockServer::start().await;
            let mut action = action();
            action.read_only = read_only;
            serve_catalog(&server, action).await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
            assert!(
                call_tool(
                    &settings(&server),
                    &McpView::Aggregate,
                    &tool_name("jira-team", "issue.view"),
                    json!({"inputs":{"issue":"ABC-1"},"outputPath":output})
                        .as_object()
                        .unwrap()
                        .clone()
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn rate_limited_tool_errors_are_the_broker_message_with_the_envelope_structured() {
        let broker_limit = "Rate limit reached for service \"jira-team\": 20 requests per 1m. Retry after 12s (at 2026-09-25T14:03:12Z). The request was not executed.";
        let upstream_limit =
            "jira-team is rate limiting requests. Retry after 30s (at 2026-09-25T14:03:30Z).";
        for (reason_code, message, result, output) in [
            (
                "rate_limited",
                broker_limit,
                json!({
                    "limitScope":"principal","service":"jira-team","limit":20,"windowSeconds":60,
                    "retryAfterSeconds":12,"retryAt":"2026-09-25T14:03:12Z",
                    "executionState":"not_dispatched","retrySafe":true
                }),
                false,
            ),
            (
                "upstream_rate_limited",
                upstream_limit,
                json!({
                    "limitScope":"upstream","service":"jira-team",
                    "retryAfterSeconds":30,"retryAt":"2026-09-25T14:03:30Z"
                }),
                true,
            ),
            (
                "concurrency_limited",
                "concurrency limit exceeded (4)",
                json!(null),
                false,
            ),
        ] {
            let server = MockServer::start().await;
            serve_catalog(&server, action()).await;
            let mut envelope = json!({
                "agentRequestId":"agent","brokerRequestId":"broker","decision":"error",
                "service":"jira-team","action":"issue.view","resourceScopes":{},
                "reasonCode":reason_code,"reason":message,"error":{"message":message}
            });
            if !result.is_null() {
                envelope["result"] = result;
            }
            Mock::given(method("POST"))
                .and(path("/v1/invoke/jira-team/issue.view"))
                .respond_with(
                    ResponseTemplate::new(429)
                        .insert_header("Retry-After", "12")
                        .set_body_json(&envelope),
                )
                .expect(1)
                .mount(&server)
                .await;
            let temp = tempfile::tempdir().unwrap();
            let destination = temp.path().join("issue.json");
            std::fs::write(&destination, "original").unwrap();
            let mut arguments = json!({"inputs":{"issue":"ABC-1"}});
            if output {
                arguments["outputPath"] = json!(destination);
            }
            let result = call_tool(
                &settings(&server),
                &McpView::Aggregate,
                &tool_name("jira-team", "issue.view"),
                arguments.as_object().unwrap().clone(),
            )
            .await
            .unwrap();
            let result = serde_json::to_value(result).unwrap();
            assert_eq!(result["isError"], true, "{reason_code}");
            assert_eq!(result["structuredContent"], envelope, "{reason_code}");
            let text = if reason_code == "concurrency_limited" {
                serde_json::to_string(&envelope).unwrap()
            } else {
                message.to_owned()
            };
            assert_eq!(
                result["content"],
                json!([{"type":"text","text":text}]),
                "{reason_code}"
            );
            assert_eq!(std::fs::read_to_string(&destination).unwrap(), "original");
        }
    }

    #[tokio::test]
    async fn discovery_file_output_saves_result_and_preserves_destination_on_error() {
        for status in [200, 403] {
            let server = MockServer::start().await;
            let body = if status == 200 {
                json!([])
            } else {
                json!({"agentRequestId":"a","brokerRequestId":"b","decision":"deny","reason":"forbidden"})
            };
            Mock::given(method("GET"))
                .and(path("/v1/services"))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
            let temp = tempfile::tempdir().unwrap();
            let destination = temp.path().join("services.json");
            std::fs::write(&destination, "original").unwrap();
            let result = call_tool(
                &settings(&server),
                &McpView::Aggregate,
                "services_list",
                json!({"outputPath":destination})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .await
            .unwrap();
            let result = serde_json::to_value(result).unwrap();
            assert_eq!(result["isError"], status != 200);
            if status == 200 {
                assert_eq!(
                    serde_json::from_slice::<Value>(&std::fs::read(destination).unwrap()).unwrap(),
                    json!({"services":[]})
                );
                assert!(result["structuredContent"].get("services").is_none());
                assert_eq!(result["structuredContent"]["output"]["sensitive"], false);
            } else {
                assert_eq!(std::fs::read_to_string(destination).unwrap(), "original");
                assert!(result["structuredContent"].get("output").is_none());
            }
        }
    }

    #[tokio::test]
    async fn broker_redirects_never_forward_identity() {
        let target = MockServer::start().await;
        let broker = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&target)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", target.uri()))
            .mount(&broker)
            .await;
        assert!(
            list_tools(&settings(&broker), &McpView::Aggregate)
                .await
                .unwrap_err()
                .to_string()
                .contains("redirects")
        );
    }

    #[tokio::test]
    async fn malformed_broker_json_is_safe_and_does_not_kill_the_server() {
        let broker = MockServer::start().await;
        serve_catalog(&broker, action()).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("upstream-password-secret"))
            .mount(&broker)
            .await;
        let error = call_tool(
            &settings(&broker),
            &McpView::Aggregate,
            &tool_name("jira-team", "issue.view"),
            json!({"inputs":{}}).as_object().unwrap().clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "broker response is not valid JSON");
        assert_eq!(
            list_tools(&settings(&broker), &McpView::Aggregate)
                .await
                .unwrap()
                .tools
                .len(),
            6
        );
    }

    #[tokio::test]
    async fn downloads_verify_hash_and_preserve_destination_on_failure() {
        use base64::Engine;
        let server = MockServer::start().await;
        let mut action = action();
        action.io = ActionIo::RawDownload {
            metadata_header: agent_access_provider::RESULT_METADATA_HEADER.into(),
            metadata_encoding: agent_access_provider::HeaderEncoding::Base64Json,
        };
        serve_catalog(&server, action).await;
        let metadata = allow(json!({"size":3,"sha256":"0".repeat(64)}));
        Mock::given(method("POST"))
            .and(header("Accept", "application/octet-stream"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        agent_access_provider::RESULT_METADATA_HEADER,
                        base64::engine::general_purpose::STANDARD
                            .encode(serde_json::to_vec(&metadata).unwrap()),
                    )
                    .set_body_bytes(b"abc".to_vec()),
            )
            .mount(&server)
            .await;
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("result");
        std::fs::write(&destination, "original").unwrap();
        let result = call_tool(
            &settings(&server),
            &McpView::Aggregate,
            &tool_name("jira-team", "issue.view"),
            json!({"inputs":{},"outputPath":destination})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(destination).unwrap(), "original");
    }

    #[tokio::test]
    async fn downloads_write_verified_bytes_and_return_structured_metadata() {
        use base64::Engine;
        let server = MockServer::start().await;
        let mut action = action();
        action.io = ActionIo::RawDownload {
            metadata_header: agent_access_provider::RESULT_METADATA_HEADER.into(),
            metadata_encoding: agent_access_provider::HeaderEncoding::Base64Json,
        };
        serve_catalog(&server, action).await;
        let metadata = allow(
            json!({"size":null,"sha256":crate::finalize_sha256(Sha256::new().chain_update(b"abc"))}),
        );
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        agent_access_provider::RESULT_METADATA_HEADER,
                        base64::engine::general_purpose::STANDARD
                            .encode(serde_json::to_vec(&metadata).unwrap()),
                    )
                    .set_body_bytes(b"abc".to_vec()),
            )
            .mount(&server)
            .await;
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("result");
        let result = call_tool(
            &settings(&server),
            &McpView::Aggregate,
            &tool_name("jira-team", "issue.view"),
            json!({"inputs":{},"outputPath":destination})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .unwrap();
        let result = serde_json::to_value(result).unwrap();
        assert_eq!(result["isError"], false);
        let mut receipt = result["structuredContent"].clone();
        let output = receipt.as_object_mut().unwrap().remove("output").unwrap();
        assert_eq!(
            receipt.as_object_mut().unwrap().remove("operationStatus"),
            Some(json!("succeeded"))
        );
        assert_eq!(receipt, metadata);
        assert_eq!(output["status"], "succeeded");
        assert_eq!(output["path"], destination.to_str().unwrap());
        assert_eq!(output["size"], 3);
        assert_eq!(output["sha256"], metadata["result"]["sha256"]);
        assert_eq!(std::fs::read(destination).unwrap(), b"abc");
    }

    #[test]
    fn cloudbees_ci_artifact_download_is_a_local_file_mcp_tool() {
        let mut action = action();
        action.action = "build.artifact.download".into();
        action.input_schema = json!({
            "type":"object",
            "required":["controller","job","buildNumber","artifactPath"],
            "properties":{
                "controller":{"type":"string"},
                "job":{"type":"string"},
                "buildNumber":{"type":"integer"},
                "artifactPath":{"type":"string"}
            },
            "additionalProperties":false
        });
        action.io = agent_access_provider::raw_download_io();
        assert!(matches!(action.io, ActionIo::RawDownload { .. }));

        let mut catalog = catalog(action.clone());
        catalog.services[0].service = "cloudbees_ci".into();
        let tools = project_catalog(&catalog, &McpView::Aggregate).unwrap();
        assert!(
            tools
                .iter()
                .any(|tool| tool.name == tool_name("cloudbees_ci", &action.action))
        );
        let schema = input_schema(&action);
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&json!({
            "inputs": {"controller":"team-ci","job":"payments/build-api","buildNumber":42,"artifactPath":"reports/tests.xml"},
            "outputPath":"/tmp/tests.xml"
        })));
        assert!(!validator.is_valid(&json!({
            "inputs": {"controller":"team-ci","job":"payments/build-api","buildNumber":42,"artifactPath":"reports/tests.xml"}
        })));
        assert!(!agent_access_core::mcp::action_eligible(
            &action,
            agent_access_core::mcp::ProjectionMode::Http
        ));
    }

    #[tokio::test]
    async fn multipart_uses_catalog_plan_and_injects_file_metadata() {
        let server = MockServer::start().await;
        let mut action = action();
        action.read_only = false;
        action.io = ActionIo::MultipartUpload {
            plan: agent_access_provider::MultipartUploadSpec::new(
                "attachment",
                "/attachments",
                "upload",
            )
            .with_file_count(1, Some(1))
            .with_metadata_fields(vec![
                "field".into(),
                "size".into(),
                "sha256".into(),
                "filename".into(),
            ]),
        };
        serve_catalog(&server, action).await;
        Mock::given(method("POST"))
            .and(path("/v1/invoke/jira-team/issue.view"))
            .respond_with(ResponseTemplate::new(200).set_body_json(allow(json!({"uploaded":true}))))
            .expect(1)
            .mount(&server)
            .await;
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("report.txt");
        std::fs::write(&file, "file contents").unwrap();
        let destination = temp.path().join("upload-response.json");
        let result = call_tool(&settings(&server), &McpView::Aggregate,
            &tool_name("jira-team", "issue.view"),
            json!({"inputs":{"issue":"ABC-1"},"files":[{"role":"attachment","path":file}],"outputPath":destination})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .unwrap();
        let result = serde_json::to_value(result).unwrap();
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["operationStatus"], "succeeded");
        assert!(result["structuredContent"].get("result").is_none());
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(destination).unwrap()).unwrap()["result"]
                ["uploaded"],
            true
        );
        let requests = server.received_requests().await.unwrap();
        let request = requests
            .iter()
            .find(|request| request.method.as_str() == "POST")
            .unwrap();
        let body = String::from_utf8_lossy(&request.body);
        assert!(body.contains("name=\"request\""));
        assert!(body.contains("name=\"upload0\""));
        assert!(body.contains("file contents"));
        assert!(body.contains("\"attachments\":[{\"field\":\"upload0\""));
        assert!(body.contains(&crate::finalize_sha256(
            Sha256::new().chain_update(b"file contents")
        )));
    }

    #[test]
    fn upload_metadata_is_from_stable_snapshot_and_sensitive_requirements_are_optional() {
        let plan = agent_access_provider::MultipartUploadSpec::new("attachment", "/files", "file")
            .with_file_count(1, Some(1))
            .with_metadata_fields(vec!["field".into(), "size".into(), "sha256".into()]);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("file.txt");
        std::fs::write(&path, "first").unwrap();
        let files = vec![crate::SendFileDescriptor {
            role: "attachment".into(),
            path: path.clone(),
            filename: None,
            content_type: None,
        }];
        let mut inputs = json!({});
        let prepared = prepare_upload(&files, &plan, &mut inputs).unwrap();
        std::fs::write(&path, "changed").unwrap();
        assert_eq!(
            std::fs::read(prepared[0].snapshot.path()).unwrap(),
            b"first"
        );
        assert_eq!(inputs["files"][0]["size"], 5);
        assert_eq!(
            inputs["files"][0]["sha256"],
            crate::finalize_sha256(Sha256::new().chain_update(b"first"))
        );
        let mut action = action();
        action.io = ActionIo::MultipartUpload { plan };
        action.input_schema = json!({"type":"object","required":["files","token","issue"],"properties":{"files":{"type":"array"},"token":{"type":"string"},"issue":{"type":"string"}}});
        action.sensitive_input_pointers = vec!["/inputs/token".into()];
        let schema = input_schema(&action);
        assert_eq!(schema["properties"]["inputs"]["required"], json!(["issue"]));
        assert!(
            schema["properties"]["files"]["items"]["properties"]
                .get("contentType")
                .is_none()
        );
    }
}
