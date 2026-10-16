//! OpenAPI 3.1 JSON discovery and frozen, single-attempt HTTP operation execution.
mod config;
mod document;
mod refs;
mod transport;

use agent_access_core::imports::*;
use agent_access_provider::*;
use async_trait::async_trait;
use config::Settings;
use document::Document;
use reqwest::Method;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use transport::*;
use url::Url;

/// The `openapi_http` import selection. OpenAPI imports use static
/// credentials only, so it declares no OAuth companion.
pub fn registration() -> ImportedAdapterRegistration {
    imported_adapter_registration(
        agent_access_provider::module_metadata!(),
        &OpenApiAdapter,
        None,
    )
}

#[derive(Debug)]
struct OpenApiAdapter;
#[async_trait]
impl ImportedAdapter for OpenApiAdapter {
    fn kind(&self) -> &'static str {
        "openapi_http"
    }
    fn development_only(&self) -> bool {
        false
    }
    fn validate_definition(&self, definition: &ImportedServiceDefinition) -> Result<(), String> {
        Settings::parse(definition).map(|_| ())
    }
    fn additional_destinations(
        &self,
        definition: &ImportedServiceDefinition,
    ) -> Result<Vec<String>, String> {
        Ok(vec![Settings::parse(definition)?.document.to_string()])
    }
    fn sensitive_output_pointers(&self) -> &'static [&'static str] {
        &["/result/upstreamHttp"]
    }
    fn validate_action(&self, action: &ImportedActionDefinition) -> Result<(), String> {
        CompiledAction::new(action).map(|_| ())
    }
    fn scoped_mcp_name(&self, action: &ImportedActionDefinition) -> Result<String, String> {
        let source = action
            .source
            .as_object()
            .ok_or("operation source must be an object")?;
        if let Some(value) = source.get("operationId") {
            return value
                .as_str()
                .filter(|name| source.len() == 1 && config::bounded(name, 256))
                .map(str::to_owned)
                .ok_or_else(|| "operation source has an invalid operationId".into());
        }
        let method = source
            .get("method")
            .and_then(Value::as_str)
            .ok_or("operation source requires method")?;
        let path = source
            .get("path")
            .and_then(Value::as_str)
            .ok_or("operation source requires path")?;
        if source.len() != 2
            || !matches!(
                method,
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            )
        {
            return Err("operation source has an invalid method/path identity".into());
        }
        document::validate_path(path)?;
        Ok(action.action.clone())
    }
    fn build(
        &self,
        definition: &ImportedServiceDefinition,
        actions: &[ImportedActionDefinition],
        transport_credential: Option<ExecutionCredential>,
        _import: &ImportedAdapterContext<'_>,
        host: &BuildContext<'_>,
    ) -> Result<ImportedProvider, ProviderBuildError> {
        let settings = Settings::parse(definition).map_err(ProviderBuildError::invalid)?;
        if transport_credential.is_some() {
            return Err(ProviderBuildError::invalid(
                "OpenAPI imports do not use transport credentials",
            ));
        }
        let mut compiled = BTreeMap::new();
        for action in actions {
            self.scoped_mcp_name(action)
                .map_err(ProviderBuildError::invalid)?;
            let action = CompiledAction::new(action).map_err(ProviderBuildError::invalid)?;
            if settings.scheme.as_deref() != Some(action.plan.security.scheme.as_str())
                || definition.execution_bindings.iter().any(|binding| {
                    action.plan.security.delivery().ok().as_ref() != Some(&binding.delivery)
                })
            {
                return Err(ProviderBuildError::invalid(
                    "accepted operation security no longer matches service credentials",
                ));
            }
            if compiled
                .insert(action.definition.action.clone(), action)
                .is_some()
            {
                return Err(ProviderBuildError::invalid("duplicate action name"));
            }
        }
        let endpoint =
            config::endpoint(&definition.endpoint).map_err(ProviderBuildError::invalid)?;
        let allowed = [format!("{}/**", endpoint.as_str().trim_end_matches('/'))];
        Ok(ImportedProvider::Upstream(Arc::new(OpenApiProvider {
            client: client(&endpoint, &allowed, host)?,
            endpoint,
            definition: definition.clone(),
            actions: compiled,
            max_bytes: host.limits().max_upstream_response_bytes as usize,
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
        let settings = Settings::parse(definition).map_err(|reason| {
            AdapterDiscoveryError::Configuration(format!(
                "OpenAPI configuration is invalid: {}",
                reason.chars().take(512).collect::<String>()
            ))
        })?;
        if transport_credential.is_some() {
            return Err(credential_error().into());
        }
        let authorization = match (&settings.document_delivery, authentication) {
            (None, ImportedDiscoveryAuthentication::Anonymous) => None,
            (Some(delivery), ImportedDiscoveryAuthentication::Static(credential)) => {
                Some(auth(delivery, credential)?)
            }
            _ => return Err(credential_error().into()),
        };
        let client =
            client(&settings.document, &[settings.document.to_string()], host).map_err(|_| {
                AdapterDiscoveryError::Configuration(
                    "OpenAPI document destination is invalid".to_owned(),
                )
            })?;
        let limit = MAX_DOCUMENT_BYTES.min(host.limits().max_upstream_response_bytes as usize);
        let operation = async {
            let mut response = client
                .send(
                    client.request(Method::GET, settings.document).header(
                        "Accept",
                        "application/json, application/vnd.oai.openapi+json",
                    ),
                    UpstreamCall::new("openapi.discover")
                        .with_authorizations(authorization.as_slice()),
                )
                .await
                .map_err(|error| {
                    ProviderError::error(error.reason_code(), "OpenAPI document request failed")
                })?;
            let status = response.status().as_u16();
            complete_upstream_trace(&mut response, None);
            if status == 429 {
                // Throttling by the document server is the upstream's rate
                // limit for this imported service, with its bounded wait.
                return Err(upstream_rate_limited(
                    &definition.service,
                    UpstreamRetryAfter::from_headers(response.headers()),
                )
                .with_upstream(Some(status), None));
            }
            if status != 200 {
                return Err(ProviderError::error(
                    status_reason(status),
                    "OpenAPI document could not be read",
                )
                .with_upstream(Some(status), None));
            }
            if !json_media(
                response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or(""),
            ) {
                return Err(protocol_error());
            }
            let bytes = read_body(response, limit).await?;
            let definition = definition.clone();
            let parse_definition = definition.clone();
            let document = tokio::task::spawn_blocking(move || {
                let value = serde_json::from_slice(&bytes)
                    .map_err(|_| "definition must be bounded JSON".to_owned())?;
                Document::new(value, &parse_definition)
            })
            .await
            .map_err(|_| protocol_error())?
            .map_err(|reason| ProviderError::error(ReasonCode::UpstreamProtocolFailed, reason))?;
            let document = Arc::new(document);
            let mut tools = Vec::new();
            let mut manifest_bytes = 0usize;
            for (path, method) in &document.operations {
                let (path, method) = (path.clone(), method.clone());
                let definition = definition.clone();
                let document = document.clone();
                // Cancellation permits at most one bounded operation compilation
                // to finish; no queued compile can continue after the deadline.
                let tool = tokio::task::spawn_blocking(move || {
                    document.operation(&definition, &path, &method)
                })
                .await
                .map_err(|_| protocol_error())?;
                manifest_bytes = manifest_bytes.saturating_add(
                    serde_json::to_vec(&tool)
                        .map_err(|_| protocol_error())?
                        .len(),
                );
                if manifest_bytes > IMPORT_MAX_MANIFEST_BYTES {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "OpenAPI discovery exceeds the imported manifest size budget",
                    ));
                }
                tools.push(tool);
            }
            Ok(ImportedDiscovery {
                protocol_version: document.version.clone(),
                metadata: document.metadata.clone(),
                tools,
                service_metadata: None,
            })
        };
        Ok(tokio::time::timeout(Duration::from_secs(60), operation)
            .await
            .map_err(|_| {
                ProviderError::error(
                    ReasonCode::UpstreamTimeout,
                    "OpenAPI discovery exceeded its deadline",
                )
            })??)
    }
}

struct OpenApiProvider {
    client: Arc<UpstreamClient>,
    endpoint: Url,
    definition: ImportedServiceDefinition,
    actions: BTreeMap<String, CompiledAction>,
    max_bytes: usize,
    timeout: Duration,
}
impl OpenApiProvider {
    /// Imported actions are action-only; their inputs must still plan a request.
    fn validate_action_inputs(&self, action: &str, inputs: &Value) -> Result<(), ProviderError> {
        self.actions
            .get(action)
            .ok_or_else(input_error)?
            .request(&self.endpoint, inputs)?;
        Ok(())
    }
}

#[async_trait]
impl Provider for OpenApiProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.validate_action_inputs(request.action(), request.inputs())?;
        Ok(ScopeResolution::no_resources())
    }
    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        if request.service() != self.definition.service
            || !matches!(request.authority(), InvocationAuthority::ActionOnly)
            || !request.body_parts().is_empty()
            || request.execution().delegated().is_some()
        {
            return Err(input_error());
        }
        let action = self.actions.get(request.action()).ok_or_else(input_error)?;
        let (url, headers) = action.request(&self.endpoint, request.inputs())?;
        let binding = self
            .definition
            .execution_bindings
            .iter()
            .find(|binding| {
                binding.owner_mode.as_str() == request.credential_mode().as_str()
                    && binding.is_supported()
                    && binding.mechanism == ImportedAuthMechanism::StaticToken
            })
            .ok_or_else(credential_error)?;
        let authorization = auth(
            &binding.delivery,
            request
                .execution()
                .static_credential()
                .ok_or_else(credential_error)?,
        )?;
        // The client adds the credential when it sends the request, in place
        // of a parameter header of the same name.
        let mut upstream = self
            .client
            .request(method(&action.plan), url)
            .headers(headers);
        let accepted_media = action
            .plan
            .responses
            .values()
            .filter_map(|response| response.content_type.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        if !accepted_media.is_empty() {
            upstream = upstream.header("Accept", accepted_media);
        }
        if let Some(body) = request.inputs().get("body") {
            upstream = upstream.json(body);
        }
        let started = Instant::now();
        let mut dispatched = false;
        let mut status = None;
        let operation = async {
            dispatched = true;
            let mut response = self
                .client
                .send(
                    upstream,
                    UpstreamCall::new(&action.definition.action).with_authorization(&authorization),
                )
                .await
                .map_err(|error| {
                    if matches!(
                        error,
                        UpstreamError::NotAllowed | UpstreamError::NotSent { .. }
                    ) {
                        dispatched = false;
                    }
                    ProviderError::error(
                        error.reason_code(),
                        "upstream HTTP operation did not complete",
                    )
                })?;
            let code = response.status().as_u16();
            status = Some(code);
            let retry_after = UpstreamRetryAfter::from_headers(response.headers());
            let selector = if action.plan.responses.contains_key(&code.to_string()) {
                code.to_string()
            } else if action
                .plan
                .responses
                .contains_key(&format!("{}XX", code / 100))
            {
                format!("{}XX", code / 100)
            } else {
                "default".into()
            };
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            complete_upstream_trace(
                &mut response,
                (!(200..300).contains(&code)).then(|| status_reason(code).into()),
            );
            let bytes = read_body(response, self.max_bytes).await?;
            let decoded = (|| {
                let spec = action
                    .plan
                    .responses
                    .get(&selector)
                    .ok_or_else(protocol_error)?;
                let body = match (&spec.content_type, &action.responses[&selector]) {
                    (None, None) if bytes.is_empty() => Value::Null,
                    (Some(media), Some(schema)) if content_type == media.to_ascii_lowercase() => {
                        let body: Value =
                            serde_json::from_slice(&bytes).map_err(|_| protocol_error())?;
                        if !schema.is_valid(&body) {
                            return Err(protocol_error());
                        }
                        body
                    }
                    _ => return Err(protocol_error()),
                };
                Ok(json!({"upstreamHttp":{"status":code,"body":body}}))
            })();
            if !(200..300).contains(&code) {
                let mut error = ProviderError::error(
                    status_reason(code),
                    "upstream rejected the HTTP operation",
                );
                // Undeclared or invalid error payloads are discarded; the known
                // HTTP failure status remains useful even without its body.
                if let Ok(value) = decoded {
                    error = error.with_result(value);
                }
                if code == 429 {
                    error = error.with_upstream_rate_limit(&self.definition.service, retry_after);
                }
                return Err(error);
            }
            let value = decoded?;
            Ok(value)
        };
        let outcome = tokio::time::timeout(self.timeout, operation)
            .await
            .unwrap_or_else(|_| {
                Err(ProviderError::error(
                    ReasonCode::UpstreamTimeout,
                    "OpenAPI operation exceeded its deadline",
                ))
            });
        let elapsed = started.elapsed().as_millis() as u64;
        let audit = json!({"adapterKind":"openapi_http","method":action.plan.method,"pathTemplate":action.plan.path,"credentialMode":request.credential_mode(),"operationDispatched":dispatched});
        match outcome {
            Ok(mut result) => {
                if !action.definition.read_only {
                    result["mutationStatus"] = json!("applied_unverified");
                    result["retrySafe"] = json!(false);
                }
                Ok(ProviderResult::new(result)
                    .with_audit(audit)
                    .with_upstream(status, Some(elapsed)))
            }
            Err(mut error) => {
                if !action.definition.read_only {
                    // Only a request the SDK refused or proved unsent was
                    // never dispatched; anything else may have been applied.
                    error = error.with_mutation_receipt(if dispatched {
                        MutationReceipt::unknown()
                    } else {
                        MutationReceipt::not_applied()
                    });
                    if let Some(result) = error.result.as_deref_mut() {
                        result["operationDispatched"] = json!(dispatched);
                    }
                }
                Err(error.with_upstream(status, Some(elapsed)).with_audit(audit))
            }
        }
    }
}
fn json_media(media: &str) -> bool {
    let media = media
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    media == "application/json" || (media.starts_with("application/") && media.ends_with("+json"))
}
fn status_reason(status: u16) -> ReasonCode {
    match status {
        401 => ReasonCode::UpstreamUnauthorized,
        403 => ReasonCode::UpstreamForbidden,
        429 => ReasonCode::UpstreamRateLimited,
        300..=399 => ReasonCode::UpstreamProtocolFailed,
        _ => ReasonCode::UpstreamFailed,
    }
}

#[cfg(test)]
mod tests;
