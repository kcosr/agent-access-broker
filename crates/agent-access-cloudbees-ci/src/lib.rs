//! CloudBees CI backend: bounded job, build, log, test, queue, archived
//! artifact, and trigger actions across configured controllers, authorized
//! against `cloudbees_ci_job` resources.
use agent_access_provider::{
    ActionDescriptor, BackendConfig, BackendRegistration, BuildContext, ClientProfile,
    CredentialDescriptor, CredentialView, EgressDeclaration, EgressProxyConfig, EgressRoute,
    ExecutionCredential, Provider, ProviderBuildError, ProviderError, ProviderFailureStatus,
    ProviderInvocation, ProviderLimits, ProviderReasonDefinition, ProviderResult,
    ProviderResultStream, ProviderStreamError, ReasonCode, RedirectRules,
    ResourceScopeCapabilities, ResourceScopes, ResourceType, ScopeRequest, ScopeResolution,
    ServiceDescriptor, ServiceSurface, UpstreamCall, UpstreamClient, UpstreamClientSpec,
    UpstreamError, UpstreamRetryAfter, ValidationContext, complete_upstream_trace,
    current_provider_action, is_service_name, parse_backend_config, upstream_rate_limited,
    url_allowed_by_patterns, validate_egress_proxy_config, validate_upstream_allowlist,
    validate_upstream_base_url,
};
use agent_access_provider::{NamespaceSelectorDescriptor, ResourceTypeDescriptor};
use async_trait::async_trait;
use futures_util::stream;
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

mod input;
mod logs;
mod reads;

use input::{JobInput, input_error};

const JSON_LIMIT: u64 = 1_048_576;
const LOG_LIMIT: u64 = 65_536;
const ARTIFACT_LIST_LIMIT: usize = 1000;

struct Controller {
    base: Url,
    web_base: Url,
    client: UpstreamClient,
    download_client: UpstreamClient,
}

pub struct CloudbeesCiProvider {
    controllers: BTreeMap<String, Controller>,
    response_limit: u64,
    download_limit: u64,
    download_idle_timeout: Duration,
    request_timeout: Duration,
    log_scan_limit: u64,
    log_signer: agent_access_provider::ContinuationSigner,
    log_fingerprint: String,
}

struct Reply {
    status: StatusCode,
    bytes: Vec<u8>,
    content_type: Option<String>,
    location: Option<String>,
    duration_ms: u64,
}

impl CloudbeesCiProvider {
    /// A provider whose clients come from a test host with `limits`.
    #[cfg(test)]
    pub(crate) fn for_tests(
        config: CloudbeesCiProviderConfig,
        limits: ProviderLimits,
    ) -> Result<Self, ProviderBuildError> {
        let host = agent_access_provider::test_support::TestHost::with_limits(limits.clone());
        Self::new(config, limits, &host)
    }

    /// One request client and one download client per controller.
    pub(crate) fn new(
        config: CloudbeesCiProviderConfig,
        limits: ProviderLimits,
        clients: &dyn agent_access_provider::host::UpstreamClientFactory,
    ) -> Result<Self, ProviderBuildError> {
        let log_fingerprint = logs::fingerprint(&config, &limits);
        let log_scan_limit = config.max_log_scan_bytes;
        let mut controllers = BTreeMap::new();
        for (alias, controller) in config.controllers {
            let base = Url::parse(&controller.base_url).expect("validated controller URL");
            let web_base = controller
                .web_base_url
                .as_deref()
                .map(Url::parse)
                .transpose()
                .expect("validated web URL")
                .unwrap_or_else(|| base.clone());
            let label = format!("providers.cloudbees_ci.controllers.{alias}");
            let client = |profile| {
                UpstreamClient::build(
                    UpstreamClientSpec {
                        label: &label,
                        provider: "cloudbees_ci",
                        base: &base,
                        egress: EgressDeclaration::Ordinary(config.egress_proxy.as_ref()),
                        allowed_upstream_hosts: &config.allowed_upstream_hosts,
                        profile,
                        status_reasons: &[],
                    },
                    clients,
                )
            };
            let download_client = client(ClientProfile::Stream)?;
            let client = client(ClientProfile::Request)?;
            controllers.insert(
                alias,
                Controller {
                    base,
                    web_base,
                    client,
                    download_client,
                },
            );
        }
        Ok(Self {
            controllers,
            log_scan_limit,
            log_signer: agent_access_provider::ContinuationSigner::new(None),
            log_fingerprint,
            response_limit: limits.max_upstream_response_bytes.min(JSON_LIMIT),
            download_limit: limits.max_download_bytes,
            download_idle_timeout: Duration::from_millis(limits.streaming_idle_timeout_ms),
            request_timeout: Duration::from_millis(limits.request_timeout_ms),
        })
    }

    fn job_url(base: &Url, job: &str) -> Url {
        let mut url = base.clone();
        {
            let mut path = url.path_segments_mut().expect("HTTP URL");
            path.pop_if_empty();
            for segment in job.split('/') {
                path.push("job").push(segment);
            }
        }
        url
    }

    fn append(mut url: Url, segments: &[&str]) -> Url {
        {
            let mut path = url.path_segments_mut().expect("HTTP URL");
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        url
    }

    fn tree(mut url: Url, fields: &str) -> Url {
        url.query_pairs_mut().append_pair("tree", fields);
        url
    }

    fn verified_web_url(
        controller: &Controller,
        candidate: Option<&str>,
        job: &str,
        build_number: Option<u64>,
    ) -> Option<String> {
        let candidate = candidate?;
        let actual = Url::parse(candidate).ok()?;
        if actual.query().is_some()
            || actual.fragment().is_some()
            || !actual.username().is_empty()
            || actual.password().is_some()
        {
            return None;
        }
        for base in [&controller.base, &controller.web_base] {
            let mut expected = Self::job_url(base, job);
            if let Some(number) = build_number {
                expected = Self::append(expected, &[&number.to_string()]);
            }
            if actual.origin() == expected.origin()
                && actual.path().trim_end_matches('/') == expected.path().trim_end_matches('/')
            {
                return Some(candidate.to_owned());
            }
        }
        None
    }

    async fn request(
        &self,
        controller: &Controller,
        credential: &ExecutionCredential,
        method: Method,
        url: Url,
        cap: u64,
    ) -> Result<Reply, ProviderError> {
        self.request_with_size_error(
            controller,
            credential,
            method,
            url,
            cap,
            response_too_large,
            None,
        )
        .await
    }

    /// The `build.trigger` POST. Once the request may have reached the
    /// controller, a timeout, transport failure, or 5xx is reported as an
    /// applied-unverified receipt rather than a retryable upstream error.
    async fn trigger_post(
        &self,
        controller: &Controller,
        credential: &ExecutionCredential,
        url: Url,
        safe_locators: &Value,
    ) -> Result<Reply, ProviderError> {
        self.request_with_size_error(
            controller,
            credential,
            Method::POST,
            url,
            4096,
            response_too_large,
            Some(safe_locators),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_with_size_error(
        &self,
        controller: &Controller,
        credential: &ExecutionCredential,
        method: Method,
        url: Url,
        cap: u64,
        size_error: fn() -> ProviderError,
        mutation: Option<&Value>,
    ) -> Result<Reply, ProviderError> {
        let (username, token) = basic_material(credential)?;
        if url.origin() != controller.base.origin()
            || !url.path().starts_with(controller.base.path())
        {
            return Err(escaped_base());
        }
        let started = Instant::now();
        let method_name = method.as_str().to_owned();
        let operation = current_provider_action()
            .map(|(_, action)| action)
            .unwrap_or_else(|| "request".into());
        let request = controller
            .client
            .request(method, url)
            .basic_auth(username, Some(token));
        let mut response = controller
            .client
            .send(request, UpstreamCall::new(&operation))
            .await
            .map_err(|error| match (error, mutation) {
                (UpstreamError::NotAllowed, _) => escaped_base(),
                // Only `NotSent` proves the controller never received the request.
                (UpstreamError::Timeout | UpstreamError::Transport(_), Some(locators)) => {
                    trigger_unverified(locators)
                }
                (error, _) => {
                    ProviderError::error(error.reason_code(), "CloudBees CI request failed")
                }
            })?;
        complete_upstream_trace(&mut response, None);
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if status == StatusCode::UNAUTHORIZED {
            return Err(ProviderError::error(
                ReasonCode::UpstreamUnauthorized,
                "CloudBees CI rejected the credential",
            ));
        }
        if status == StatusCode::FORBIDDEN {
            return Err(ProviderError::error(
                ReasonCode::UpstreamForbidden,
                "CloudBees CI denied this operation",
            ));
        }
        if status == StatusCode::CONFLICT && method_name == "POST" {
            return Err(ProviderError::deny(
                ReasonCode::VerificationMismatch,
                "CloudBees CI job is not buildable",
            ));
        }
        if status.is_redirection() {
            return Err(protocol_error());
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(rate_limited(response.headers()));
        }
        if status.is_server_error()
            && let Some(locators) = mutation
        {
            return Err(trigger_unverified(locators).with_upstream(
                Some(status.as_u16()),
                Some(started.elapsed().as_millis() as u64),
            ));
        }
        if !status.is_success() && status != StatusCode::NOT_FOUND {
            return Err(ProviderError::error(
                ReasonCode::UpstreamFailed,
                "CloudBees CI returned an unexpected status",
            ));
        }
        if status == StatusCode::NOT_FOUND || method_name == "POST" {
            return Ok(Reply {
                status,
                bytes: Vec::new(),
                content_type,
                location,
                duration_ms: started.elapsed().as_millis() as u64,
            });
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            ProviderError::error(
                if error.is_timeout() {
                    ReasonCode::UpstreamTimeout
                } else {
                    ReasonCode::UpstreamConnectionFailed
                },
                "CloudBees CI response failed",
            )
        })? {
            if bytes.len() as u64 + chunk.len() as u64 > cap {
                return Err(size_error());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Reply {
            status,
            bytes,
            content_type,
            location,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    }

    async fn json(
        &self,
        controller: &Controller,
        credential: &ExecutionCredential,
        url: Url,
    ) -> Result<(Value, Reply), ProviderError> {
        self.json_with_size_error(controller, credential, url, response_too_large)
            .await
    }

    async fn json_with_size_error(
        &self,
        controller: &Controller,
        credential: &ExecutionCredential,
        url: Url,
        size_error: fn() -> ProviderError,
    ) -> Result<(Value, Reply), ProviderError> {
        let reply = self
            .request_with_size_error(
                controller,
                credential,
                Method::GET,
                url,
                self.response_limit,
                size_error,
                None,
            )
            .await?;
        if reply.status == StatusCode::NOT_FOUND {
            return Err(upstream_not_found("CloudBees CI object was not found"));
        }
        let value = parse_json(&reply)?;
        Ok((value, reply))
    }

    async fn artifacts(
        &self,
        controller: &Controller,
        credential: &ExecutionCredential,
        job_url: &Url,
        build_number: u64,
    ) -> Result<(Vec<Value>, Reply), ProviderError> {
        let url = Self::tree(
            Self::append(job_url.clone(), &[&build_number.to_string(), "api", "json"]),
            &format!(
                "number,artifacts[relativePath,fileName]{{0,{}}}",
                ARTIFACT_LIST_LIMIT + 1
            ),
        );
        let (data, reply) = self.json(controller, credential, url).await?;
        if data.get("number").and_then(Value::as_u64) != Some(build_number) {
            return Err(protocol_error());
        }
        let raw = data
            .get("artifacts")
            .and_then(Value::as_array)
            .ok_or_else(protocol_error)?;
        if raw.len() > ARTIFACT_LIST_LIMIT {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "CloudBees CI artifact list exceeds limit",
            ));
        }
        let mut artifacts = Vec::with_capacity(raw.len());
        for item in raw {
            let path = item
                .get("relativePath")
                .and_then(Value::as_str)
                .ok_or_else(protocol_error)?;
            if !valid_artifact_path(path) {
                return Err(protocol_error());
            }
            let file_name = path.rsplit('/').next().expect("validated path");
            artifacts.push(json!({"artifactPath":path,"fileName":file_name}));
        }
        Ok((artifacts, reply))
    }

    async fn artifact_response(
        &self,
        controller: &Controller,
        credential: &ExecutionCredential,
        initial: Url,
    ) -> Result<(reqwest::Response, u64), ProviderError> {
        let (username, token) = basic_material(credential)?;
        let base = &controller.base;
        let same_artifact_path = |url: &Url| {
            url.path() == initial.path() || url.path().strip_suffix('/') == Some(initial.path())
        };
        let vet = |url: &Url| {
            let same_controller = url.origin() == base.origin();
            url.fragment().is_none()
                && (same_controller || url.scheme() == "https")
                && (!same_controller || (url.query().is_none() && same_artifact_path(url)))
        };
        let started = Instant::now();
        let mut response = controller
            .download_client
            .get_following_redirects(
                initial.clone(),
                RedirectRules {
                    max_redirects: 3,
                    deadline: self.request_timeout,
                    correlate_other_origins: false,
                    vet: &vet,
                    decorate: &|request| {
                        request.header(reqwest::header::ACCEPT_ENCODING, "identity")
                    },
                    authorize: &|request| request.basic_auth(username, Some(token)),
                },
                "build.artifact.download",
            )
            .await
            .map_err(|error| match error {
                UpstreamError::Timeout
                | UpstreamError::NotSent {
                    timed_out: true, ..
                } => ProviderError::error(
                    ReasonCode::UpstreamTimeout,
                    "CloudBees CI artifact response headers timed out",
                ),
                UpstreamError::Transport(_) | UpstreamError::NotSent { .. } => {
                    ProviderError::error(
                        ReasonCode::UpstreamConnectionFailed,
                        "CloudBees CI artifact request failed",
                    )
                }
                UpstreamError::NotAllowed | UpstreamError::Redirect => protocol_error(),
            })?;
        complete_upstream_trace(&mut response, None);
        match response.status() {
            StatusCode::UNAUTHORIZED => {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamUnauthorized,
                    "CloudBees CI rejected the artifact credential",
                ));
            }
            StatusCode::FORBIDDEN => {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamForbidden,
                    "CloudBees CI denied artifact access",
                ));
            }
            StatusCode::NOT_FOUND => {
                return Err(ProviderError::deny(
                    ReasonCode::ResourceNotFound,
                    "CloudBees CI artifact was not found",
                ));
            }
            StatusCode::TOO_MANY_REQUESTS => return Err(rate_limited(response.headers())),
            status if !status.is_success() => {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamFailed,
                    "CloudBees CI artifact request failed",
                ));
            }
            _ => {}
        }
        if response
            .content_length()
            .is_some_and(|size| size > self.download_limit)
        {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "CloudBees CI artifact exceeds download limit",
            ));
        }
        Ok((response, started.elapsed().as_millis() as u64))
    }

    fn result(
        &self,
        action: &str,
        input: &JobInput<'_>,
        value: Value,
        reply: &Reply,
        proxy: &EgressRoute,
    ) -> ProviderResult {
        let queue_id = input
            .queue_id
            .or_else(|| value.get("queueId").and_then(Value::as_u64));
        let mut value = value;
        let mut audit = json!({
            "provider": "cloudbees_ci", "operation": action,
            "job": format!("{}/{}", input.controller, input.job),
            "buildNumber": input.build_number, "queueId": queue_id,
            "egressProxy": proxy.audit_value(),
        });
        // Build-level results always name the numeric build they read.
        if let (Some(number), Some(object)) = (input.build_number, value.as_object_mut()) {
            object.entry("buildNumber").or_insert(json!(number));
            if let Some(selector) = input.build_selector {
                object.insert("buildSelector".into(), json!(selector));
                audit["buildSelector"] = json!(selector);
            }
        }
        ProviderResult::new(value)
            .with_audit(audit)
            .with_upstream(Some(reply.status.as_u16()), Some(reply.duration_ms))
            .with_object_ids(json!({
                "job": format!("{}/{}", input.controller, input.job),
                "buildNumber": input.build_number, "queueId": queue_id,
            }))
    }
}

/// CloudBees CI jobs, identified as `controller/full/job/name`. Namespaces
/// cover a controller or a folder beneath it.
pub static CLOUDBEES_CI_JOB_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("cloudbees_ci_job"),
    "CloudBees CI job",
    "CloudBees CI jobs",
    "team-ci/payments/build-api",
    |value| is_cloudbees_ci_resource_path(value, false),
)
.with_namespace(NamespaceSelectorDescriptor::new(
    |value| is_cloudbees_ci_resource_path(value, true),
    "Jobs under a controller or folder",
    "Jobs",
    "team-ci/payments",
))
.with_action_inputs(input::job_action_inputs);

/// CloudBees CI jobs across configured controllers.
pub fn cloudbees_ci_descriptor(_config: &CloudbeesCiProviderConfig) -> ServiceDescriptor {
    cloudbees_ci_service_descriptor()
}

// The action set does not vary with configuration.
fn cloudbees_ci_service_descriptor() -> ServiceDescriptor {
    let mut actions = Vec::new();
    for (name, description) in [
        ("job.view", "View a CloudBees CI job"),
        ("build.list", "List recent builds of a job"),
        ("build.view", "View a build"),
        (
            "build.log.read",
            "Read the beginning, end, or literal matches of a console log. Defaults to tail, 16 KiB text. Each call scans from the beginning up to the configured scan ceiling (default 16 MiB); cursors replay their prefix. Tail must reach EOF. Raising maxBytes cannot fix a scan limit.",
        ),
        ("build.artifact.list", "List archived build artifacts"),
        (
            "build.artifact.download",
            "Download an archived build artifact",
        ),
        ("build.tests.view", "View a build test summary"),
        ("queue.view", "View a queued build for a job"),
        ("build.trigger", "Trigger a non-parameterized job"),
    ] {
        let action = ActionDescriptor::new(name, description, input::schema(name))
            .documentation(input::documentation(name))
            .scope("job")
            .credential_modes(["service", "per_user"]);
        let action = match name {
            "job.view"
            | "build.list"
            | "build.view"
            | "build.tests.view"
            | "build.log.read"
            | "build.artifact.list"
            | "build.artifact.download"
            | "queue.view" => action.read_only(),
            _ => action,
        };
        actions.push(if name == "build.artifact.download" {
            action.raw_download()
        } else {
            action
        });
    }
    actions.extend(reads::descriptors());
    ServiceDescriptor {
        service: "cloudbees_ci".into(),
        display_name: "CloudBees CI".into(),
        surface: ServiceSurface::Invoke,
        resource_scopes: BTreeMap::from([(
            "job".into(),
            ResourceScopeCapabilities {
                resource_type: crate::CLOUDBEES_CI_JOB_RESOURCE.id().clone(),
                selectors: vec!["exact".into(), "namespace".into(), "all".into()],
            },
        )]),
        actions,
        credentials: CredentialDescriptor::default()
            .service_kinds(&["basic_api_token"])
            .profile("cloudbees-ci-api-token", "basic_api_token"),
        presentation_body_limit: None,
    }
}

impl CloudbeesCiProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        let input = self.parse(action, inputs)?;
        Ok(BTreeMap::from([(
            "job".into(),
            vec![format!("{}/{}", input.controller, input.job)],
        )]))
    }
}

#[async_trait]
impl Provider for CloudbeesCiProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    fn resource_roots(&self, resource_type: &ResourceType) -> Vec<String> {
        if resource_type == CLOUDBEES_CI_JOB_RESOURCE.id() {
            self.controllers.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        if !request.body_parts().is_empty() {
            return Err(input_error(
                "value_invalid",
                None,
                "CloudBees CI actions take no file parts",
            ));
        }
        let mut input = self.parse(request.action(), request.inputs())?;
        let controller = self
            .controllers
            .get(&input.controller)
            .expect("validated controller");
        let credential = request
            .execution()
            .static_credential()
            .ok_or_else(credential_invalid)?;
        let job_url = Self::job_url(&controller.base, &input.job);
        match self
            .dispatch(
                &request,
                &mut input,
                controller,
                credential,
                job_url.clone(),
            )
            .await
        {
            Err(error)
                if error.reason_code() == ReasonCode::ResourceNotFound
                    && error.upstream_status == Some(404) =>
            {
                Err(self
                    .explain_not_found(error, &input, controller, credential, job_url)
                    .await)
            }
            outcome => outcome,
        }
    }
}

impl CloudbeesCiProvider {
    /// Resolves a permalink with one projected job read that also confirms
    /// the job identity and that the item has builds at all.
    async fn resolve_build_selector(
        &self,
        controller: &Controller,
        credential: &ExecutionCredential,
        job_url: &Url,
        job: &str,
        selector: &'static str,
    ) -> Result<u64, ProviderError> {
        let url = Self::tree(
            Self::append(job_url.clone(), &["api", "json"]),
            &format!("fullName,_class,builds[number]{{0,0}},{selector}[number]"),
        );
        let (data, _) = self.json(controller, credential, url).await?;
        check_job_identity(&data, job)?;
        if data.get("builds").is_none() {
            return Err(input::job_is_container(&data));
        }
        match data.get(selector) {
            None | Some(Value::Null) => Err(ProviderError::deny(
                ReasonCode::ResourceNotFound,
                format!("CloudBees CI job has no {selector}"),
            )
            .with_result(json!({"buildSelector":selector}))),
            Some(build) => build
                .get("number")
                .and_then(Value::as_u64)
                .filter(|number| (1..=u64::from(u32::MAX)).contains(number))
                .ok_or_else(protocol_error),
        }
    }

    /// Makes an upstream 404 actionable: a numeric build read on a folder or
    /// multibranch project becomes `job_is_container` (one job-level read in
    /// the authorized scope), and a job repeating its controller alias gets a
    /// hint. Otherwise the original error is kept.
    async fn explain_not_found(
        &self,
        mut error: ProviderError,
        input: &JobInput<'_>,
        controller: &Controller,
        credential: &ExecutionCredential,
        job_url: Url,
    ) -> ProviderError {
        if input.build_number.is_some() && input.build_selector.is_none() {
            let url = Self::tree(
                Self::append(job_url, &["api", "json"]),
                "fullName,_class,builds[number]{0,0}",
            );
            if let Ok((data, _)) = self.json(controller, credential, url).await
                && data.get("fullName").and_then(Value::as_str) == Some(input.job.as_str())
                && data.get("builds").is_none()
            {
                return input::job_is_container(&data);
            }
        }
        if input.job.starts_with(&format!("{}/", input.controller)) {
            error.message = format!(
                "{}; job repeats the controller alias: job is the full name below the controller, so omit the leading \"{}/\"",
                error.message, input.controller
            );
        } else if input::has_url_job_segments(&input.job) {
            // A folder may really be named "job", so this shape is only a hint.
            error.message = format!(
                "{}; job looks like Jenkins URL segments: for job/payments/job/build-api pass payments/build-api, or pass the URL as url",
                error.message
            );
        }
        error
    }

    async fn dispatch(
        &self,
        request: &ProviderInvocation,
        input: &mut JobInput<'_>,
        controller: &Controller,
        credential: &ExecutionCredential,
        job_url: Url,
    ) -> Result<ProviderResult, ProviderError> {
        if let Some(selector) = input.build_selector
            && input.build_number.is_none()
        {
            input.build_number = Some(
                self.resolve_build_selector(controller, credential, &job_url, &input.job, selector)
                    .await?,
            );
        }
        let input: &JobInput<'_> = input;
        if request.action() == "build.artifact.download" {
            let number = input.build_number.expect("required");
            let path = input.artifact_path.expect("required");
            let (artifacts, _) = self
                .artifacts(controller, credential, &job_url, number)
                .await?;
            let item = artifacts
                .iter()
                .find(|item| item["artifactPath"] == path)
                .ok_or_else(|| {
                    ProviderError::deny(
                        ReasonCode::ResourceNotFound,
                        "CloudBees CI artifact was not found",
                    )
                })?;
            let mut url = Self::append(job_url, &[&number.to_string(), "artifact"]);
            {
                let mut segments = url.path_segments_mut().map_err(|_| protocol_error())?;
                for segment in path.split('/') {
                    segments.push(segment);
                }
            }
            let (response, duration_ms) =
                self.artifact_response(controller, credential, url).await?;
            let status = response.status();
            let size = response.content_length();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_owned();
            let cap = self.download_limit;
            let idle = self.download_idle_timeout;
            let byte_stream =
                stream::try_unfold((response, 0_u64), move |(mut response, size)| async move {
                    let chunk = tokio::time::timeout(idle, response.chunk())
                        .await
                        .map_err(|_| {
                            ProviderStreamError::new(
                                ReasonCode::UpstreamTimeout,
                                "CloudBees CI artifact download stalled",
                            )
                        })?
                        .map_err(|error| {
                            ProviderStreamError::new(
                                if error.is_timeout() {
                                    ReasonCode::UpstreamTimeout
                                } else {
                                    ReasonCode::UpstreamConnectionFailed
                                },
                                "CloudBees CI artifact download failed",
                            )
                        })?;
                    let Some(chunk) = chunk else {
                        return Ok(None);
                    };
                    let next = size.checked_add(chunk.len() as u64).ok_or_else(|| {
                        ProviderStreamError::new(
                            ReasonCode::AttachmentSizeDenied,
                            "CloudBees CI artifact exceeds download limit",
                        )
                    })?;
                    if next > cap {
                        return Err(ProviderStreamError::new(
                            ReasonCode::AttachmentSizeDenied,
                            "CloudBees CI artifact exceeds download limit",
                        ));
                    }
                    Ok(Some((chunk, (response, next))))
                });
            let value = json!({"controller":input.controller,"job":&input.job,
                "buildNumber":number,"artifactPath":path,"fileName":item["fileName"],
                "contentType":content_type,"size":size});
            let reply = Reply {
                status,
                bytes: Vec::new(),
                content_type: None,
                location: None,
                duration_ms,
            };
            let mut result = self.result(
                request.action(),
                input,
                value,
                &reply,
                controller.client.egress_route(),
            );
            let mut stream = ProviderResultStream::from_stream(content_type, byte_stream);
            if let Some(size) = size {
                stream = stream.with_expected_size(
                    size,
                    "CloudBees CI artifact response size did not match Content-Length",
                );
            }
            result.stream = Some(stream);
            return Ok(result);
        }
        if reads::is_action(request.action()) {
            return self
                .invoke_read(request.action(), input, controller, credential, job_url)
                .await;
        }
        let job_api = Self::append(job_url.clone(), &["api", "json"]);
        let (value, reply) = match request.action() {
            "job.view" => {
                let (data, reply) = self
                    .json(controller, credential, Self::tree(job_api, "fullName,_class,displayName,url,description,buildable,inQueue,lastBuild[number],property[parameterDefinitions[name,type]]"))
                    .await?;
                check_job_identity(&data, &input.job)?;
                let params = data.get("property").and_then(Value::as_array).into_iter().flatten()
                    .flat_map(|property| property.get("parameterDefinitions").and_then(Value::as_array).into_iter().flatten())
                    .map(|parameter| json!({"name":parameter.get("name"),"type":parameter.get("type")}))
                    .collect::<Vec<_>>();
                let mut result = json!({"controller":input.controller,"job":&input.job,
                    "kind":data.get("_class"),"displayName":data.get("displayName"),
                    "description":data.get("description"),"buildable":data.get("buildable"),
                    "inQueue":data.get("inQueue"),
                    "lastBuild":data.get("lastBuild").and_then(|v| v.get("number")),
                    "parameters":params});
                if let Some(url) = Self::verified_web_url(
                    controller,
                    data.get("url").and_then(Value::as_str),
                    &input.job,
                    None,
                ) {
                    result["url"] = json!(url);
                }
                (result, reply)
            }
            "build.list" => {
                let mut url = job_api;
                url.query_pairs_mut().append_pair(
                    "tree",
                    &format!(
                        "fullName,_class,builds[number,url,result,building,timestamp,duration]{{0,{}}}",
                        input.max_results
                    ),
                );
                let (data, reply) = self.json(controller, credential, url).await?;
                check_job_identity(&data, &input.job)?;
                let builds = data
                    .get("builds")
                    .ok_or_else(|| input::job_is_container(&data))?
                    .as_array()
                    .ok_or_else(protocol_error)?;
                if builds.len() > input.max_results as usize {
                    return Err(protocol_error());
                }
                let builds = builds
                    .iter()
                    .map(|build| {
                        let mut item = json!({
                            "number":build.get("number"),"result":build.get("result"),
                            "building":build.get("building"),"timestamp":build.get("timestamp"),
                            "duration":build.get("duration"),
                        });
                        if let Some(number) = build.get("number").and_then(Value::as_u64)
                            && let Some(url) = Self::verified_web_url(
                                controller,
                                build.get("url").and_then(Value::as_str),
                                &input.job,
                                Some(number),
                            )
                        {
                            item["url"] = json!(url);
                        }
                        item
                    })
                    .collect::<Vec<_>>();
                (
                    json!({"controller":input.controller,"job":&input.job,"builds":builds}),
                    reply,
                )
            }
            "build.view" => {
                let number = input.build_number.expect("required");
                let url = Self::tree(
                    Self::append(job_url.clone(), &[&number.to_string(), "api", "json"]),
                    "number,url,displayName,result,building,timestamp,duration,estimatedDuration",
                );
                let (data, reply) = self.json(controller, credential, url).await?;
                if data.get("number").and_then(Value::as_u64) != Some(number) {
                    return Err(protocol_error());
                }
                let mut result = json!({"controller":input.controller,"job":&input.job,"number":number,
                    "displayName":data.get("displayName"),"result":data.get("result"),
                    "building":data.get("building"),"timestamp":data.get("timestamp"),
                    "duration":data.get("duration"),"estimatedDuration":data.get("estimatedDuration")});
                if let Some(url) = Self::verified_web_url(
                    controller,
                    data.get("url").and_then(Value::as_str),
                    &input.job,
                    Some(number),
                ) {
                    result["url"] = json!(url);
                }
                (result, reply)
            }
            "build.artifact.list" => {
                let number = input.build_number.expect("required");
                let (artifacts, reply) = self
                    .artifacts(controller, credential, &job_url, number)
                    .await?;
                (
                    json!({"controller":input.controller,"job":&input.job,
                    "buildNumber":number,"artifacts":artifacts}),
                    reply,
                )
            }
            "build.log.read" => {
                return self
                    .read_log(request, input, controller, credential, job_url)
                    .await;
            }
            "build.tests.view" => {
                let number = input.build_number.expect("required");
                let url = Self::tree(
                    Self::append(
                        job_url.clone(),
                        &[&number.to_string(), "testReport", "api", "json"],
                    ),
                    "totalCount,failCount,skipCount,passCount,duration",
                );
                let reply = self
                    .request(
                        controller,
                        credential,
                        Method::GET,
                        url,
                        self.response_limit,
                    )
                    .await?;
                if reply.status == StatusCode::NOT_FOUND {
                    let build_url = Self::tree(
                        Self::append(job_url, &[&number.to_string(), "api", "json"]),
                        "number",
                    );
                    let (build, _) = self.json(controller, credential, build_url).await?;
                    if build.get("number").and_then(Value::as_u64) != Some(number) {
                        return Err(protocol_error());
                    }
                    (
                        json!({"controller":input.controller,"job":&input.job,"buildNumber":number,
                        "reportAvailable":false}),
                        reply,
                    )
                } else {
                    let data = parse_json(&reply)?;
                    (
                        json!({"controller":input.controller,"job":&input.job,"buildNumber":number,
                        "reportAvailable":true,"totalCount":data.get("totalCount"),
                        "failCount":data.get("failCount"),"skipCount":data.get("skipCount"),
                        "passCount":data.get("passCount"),"duration":data.get("duration")}),
                        reply,
                    )
                }
            }
            "queue.view" => {
                let queue_id = input.queue_id.expect("required");
                let url = Self::tree(
                    Self::append(
                        controller.base.clone(),
                        &["queue", "item", &queue_id.to_string(), "api", "json"],
                    ),
                    "id,blocked,buildable,cancelled,stuck,why,task[fullName],executable[number]",
                );
                let (data, reply) =
                    self.json(controller, credential, url)
                        .await
                        .map_err(|error| {
                            if error.reason_code() == ReasonCode::ResourceNotFound {
                                ProviderError::deny(
                                    ReasonCode::ScopeUnresolved,
                                    "queue item does not identify the authorized job",
                                )
                            } else {
                                error
                            }
                        })?;
                if data.get("id").and_then(Value::as_u64) != Some(queue_id)
                    || data.pointer("/task/fullName").and_then(Value::as_str)
                        != Some(input.job.as_str())
                {
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "queue item does not identify the authorized job",
                    ));
                }
                (
                    json!({"controller":input.controller,"job":&input.job,"queueId":queue_id,
                    "blocked":data.get("blocked"),"buildable":data.get("buildable"),
                    "cancelled":data.get("cancelled"),"stuck":data.get("stuck"),
                    "why":data.get("why"),"buildNumber":data.pointer("/executable/number")}),
                    reply,
                )
            }
            "build.trigger" => {
                let (data, _) = self
                    .json(
                        controller,
                        credential,
                        Self::tree(
                            job_api,
                            "fullName,buildable,property[parameterDefinitions[name,type]]",
                        ),
                    )
                    .await?;
                check_job_identity(&data, &input.job)?;
                if data.get("buildable").and_then(Value::as_bool) != Some(true) {
                    return Err(ProviderError::deny(
                        ReasonCode::VerificationMismatch,
                        "job is not buildable",
                    ));
                }
                if data.get("property").and_then(Value::as_array).is_none() {
                    return Err(protocol_error());
                }
                if data["property"]
                    .as_array()
                    .expect("checked")
                    .iter()
                    .any(|p| {
                        p.get("parameterDefinitions")
                            .and_then(Value::as_array)
                            .is_some_and(|v| !v.is_empty())
                    })
                {
                    return Err(ProviderError::deny(
                        ReasonCode::VerificationMismatch,
                        "parameterized jobs are not supported",
                    ));
                }
                let url = Self::append(job_url, &["build"]);
                let safe_locators = json!({"controller":input.controller,"job":input.job});
                let reply = self
                    .trigger_post(controller, credential, url, &safe_locators)
                    .await?;
                if reply.status == StatusCode::NOT_FOUND {
                    return Err(upstream_not_found("CloudBees CI object was not found"));
                }
                let queue = reply.location.as_deref().and_then(|location| {
                    queue_id_from_location(&controller.base, &controller.web_base, location)
                });
                let queue_url = queue.and_then(|_| {
                    reply
                        .location
                        .as_deref()
                        .and_then(|location| controller.base.join(location).ok())
                        .map(|url| url.to_string())
                });
                let value = if queue.is_some() {
                    json!({"controller":input.controller,"job":&input.job,
                        "queueId":queue,"queueUrl":queue_url,"mutationStatus":"applied","retrySafe":false})
                } else {
                    json!({"controller":input.controller,"job":&input.job,
                        "mutationStatus":"applied_unverified","retrySafe":false,
                        "verificationStage":"mutation_response",
                        "safeLocators":safe_locators})
                };
                (value, reply)
            }
            _ => unreachable!(),
        };
        Ok(self.result(
            request.action(),
            input,
            value,
            &reply,
            controller.client.egress_route(),
        ))
    }
}

fn queue_id_from_location(base: &Url, web_base: &Url, location: &str) -> Option<u64> {
    let url = base.join(location).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    [base, web_base].into_iter().find_map(|candidate| {
        if url.origin() != candidate.origin() {
            return None;
        }
        let suffix = url
            .path()
            .strip_prefix(candidate.path())?
            .trim_end_matches('/');
        let parts = suffix.split('/').collect::<Vec<_>>();
        if parts.len() != 3 || parts[0] != "queue" || parts[1] != "item" {
            return None;
        }
        parts[2]
            .parse::<u64>()
            .ok()
            .filter(|id| *id > 0 && *id <= i64::MAX as u64)
    })
}

fn check_job_identity(value: &Value, job: &str) -> Result<(), ProviderError> {
    if value.get("fullName").and_then(Value::as_str) != Some(job) {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "CloudBees CI item does not identify the authorized job",
        ));
    }
    Ok(())
}
fn valid_artifact_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment.chars().any(|c| c.is_control() || c == '\\')
        })
}
fn parse_json(reply: &Reply) -> Result<Value, ProviderError> {
    if !reply.content_type.as_deref().is_some_and(|content_type| {
        content_type.starts_with("application/json") || content_type.contains("+json")
    }) {
        return Err(protocol_error());
    }
    serde_json::from_slice(&reply.bytes).map_err(|_| protocol_error())
}
/// A controller 404. The upstream status lets `invoke` explain it.
fn upstream_not_found(message: &'static str) -> ProviderError {
    ProviderError::deny(ReasonCode::ResourceNotFound, message).with_upstream(Some(404), None)
}

/// The `mutation_verification_failed` receipt for a trigger POST that may
/// have reached the controller without a confirming response.
fn trigger_unverified(safe_locators: &Value) -> ProviderError {
    ProviderError::error(
        ReasonCode::MutationVerificationFailed,
        "CloudBees CI did not confirm the build trigger; a build may already be queued. Do not retry automatically; check job.view (inQueue, lastBuild) or build.list first.",
    )
    .with_result(json!({
        "mutationStatus": "applied_unverified",
        "retrySafe": false,
        "verificationStage": "mutation_response",
        "safeLocators": safe_locators,
    }))
}
/// CloudBees CI authenticates with a non-empty Basic username and API token.
pub(crate) fn basic_material(
    credential: &ExecutionCredential,
) -> Result<(&str, &str), ProviderError> {
    match credential.view() {
        CredentialView::Basic { username, token } if !username.is_empty() && !token.is_empty() => {
            Ok((username, token))
        }
        CredentialView::Basic { .. } | CredentialView::Bearer { .. } => Err(credential_invalid()),
    }
}

fn credential_invalid() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialInvalid,
        "CloudBees CI requires a Basic API token",
    )
}
fn escaped_base() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "controller URL escaped configured base",
    )
}

fn response_too_large() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "CloudBees CI response exceeds limit",
    )
}

fn protocol_error() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "CloudBees CI returned an invalid response",
    )
}

/// A controller's HTTP 429, with the wait its `Retry-After` names.
fn rate_limited(headers: &reqwest::header::HeaderMap) -> ProviderError {
    upstream_rate_limited("cloudbees_ci", UpstreamRetryAfter::from_headers(headers))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudbeesCiProviderConfig {
    #[serde(default = "logs::default_scan_limit")]
    pub max_log_scan_bytes: u64,
    pub controllers: BTreeMap<String, CloudbeesCiControllerConfig>,
    pub egress_proxy: Option<EgressProxyConfig>,
    #[serde(default)]
    pub allowed_upstream_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudbeesCiControllerConfig {
    pub base_url: String,
    pub web_base_url: Option<String>,
}

/// A Pipeline node log whose text exceeds the bounded read limit.
pub static CLOUDBEES_CI_LOG_CHUNK_EXCEEDED: ProviderReasonDefinition =
    ProviderReasonDefinition::deny(
        "cloudbees_ci_log_chunk_exceeded",
        ProviderFailureStatus::ContentTooLarge,
    );

/// A `tail` log read the scan ceiling stopped before the log end.
pub static CLOUDBEES_CI_LOG_SCAN_EXCEEDED: ProviderReasonDefinition =
    ProviderReasonDefinition::deny(
        "cloudbees_ci_log_scan_exceeded",
        ProviderFailureStatus::ContentTooLarge,
    );

pub static CLOUDBEES_CI_BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    "cloudbees_ci",
    parse_backend_config::<CloudbeesCiProviderConfig>,
)
.with_resource_types(&[&CLOUDBEES_CI_JOB_RESOURCE])
.with_domain_reasons(&[
    &CLOUDBEES_CI_LOG_CHUNK_EXCEEDED,
    &CLOUDBEES_CI_LOG_SCAN_EXCEEDED,
]);

impl BackendConfig for CloudbeesCiProviderConfig {
    fn kind(&self) -> &'static str {
        "cloudbees_ci"
    }

    fn validate(&self, context: &ValidationContext<'_>, errors: &mut Vec<String>) {
        if self.max_log_scan_bytes == 0
            || self.max_log_scan_bytes > context.limits.max_upstream_response_bytes
        {
            errors.push("providers.cloudbees_ci.max_log_scan_bytes must be positive and no larger than limits.max_upstream_response_bytes".into());
        }
        if self.controllers.is_empty() {
            errors.push("providers.cloudbees_ci.controllers must not be empty".to_string());
        }
        validate_egress_proxy_config(
            "providers.cloudbees_ci.egress_proxy",
            self.egress_proxy.as_ref(),
            errors,
        );
        validate_upstream_allowlist(
            "providers.cloudbees_ci.allowed_upstream_hosts",
            &self.allowed_upstream_hosts,
            context.production(),
            errors,
        );
        for (alias, controller) in &self.controllers {
            if !is_service_name(alias) {
                errors.push(format!(
                    "providers.cloudbees_ci.controllers.{alias} has an invalid alias"
                ));
            }
            let label = format!("providers.cloudbees_ci.controllers.{alias}.base_url");
            if let Some(base) = validate_upstream_base_url(
                &label,
                &controller.base_url,
                context.production(),
                errors,
            ) {
                if !controller.base_url.ends_with('/') || base.as_str() != controller.base_url {
                    errors.push(format!("{label} must be a normalized URL ending in /"));
                }
                if base.path().contains("//") {
                    errors.push(format!("{label} must not contain empty path segments"));
                }
                if let Ok(probe) = base.join("job/probe/api/json")
                    && !url_allowed_by_patterns(&probe, &self.allowed_upstream_hosts)
                {
                    errors.push(format!(
                        "{label} is not covered by providers.cloudbees_ci.allowed_upstream_hosts"
                    ));
                }
            }
            if let Some(web_base_url) = &controller.web_base_url {
                let web_label = format!("providers.cloudbees_ci.controllers.{alias}.web_base_url");
                if let Some(web) = validate_upstream_base_url(
                    &web_label,
                    web_base_url,
                    context.production(),
                    errors,
                ) {
                    if !web_base_url.ends_with('/') || web.as_str() != web_base_url {
                        errors.push(format!("{web_label} must be a normalized URL ending in /"));
                    }
                    if web.path().contains("//") {
                        errors.push(format!("{web_label} must not contain empty path segments"));
                    }
                }
            }
        }
    }

    fn descriptor(&self) -> ServiceDescriptor {
        cloudbees_ci_descriptor(self)
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        self.egress_proxy
            .iter()
            .map(|proxy| ("providers.cloudbees_ci.egress_proxy".to_string(), proxy))
            .collect()
    }

    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        let mut provider =
            CloudbeesCiProvider::new(self.clone(), host.limits().clone(), host.clients())?;
        provider.log_signer =
            agent_access_provider::ContinuationSigner::new(host.stable_signing_key().cloned());
        Ok(Arc::new(provider))
    }
}

/// Whether `value` is a canonical `controller/job/...` path, or a bare
/// controller alias when `allow_controller_only` is set.
pub fn is_cloudbees_ci_resource_path(value: &str, allow_controller_only: bool) -> bool {
    let mut segments = value.split('/');
    let Some(controller) = segments.next() else {
        return false;
    };
    if !is_service_name(controller) {
        return false;
    }
    let job_segments: Vec<_> = segments.collect();
    (allow_controller_only || !job_segments.is_empty())
        && job_segments.iter().all(|segment| {
            !segment.is_empty()
                && *segment != "."
                && *segment != ".."
                && segment.trim() == *segment
                && !segment.chars().any(|c| {
                    c.is_control()
                        || matches!(
                            c,
                            '?' | '*'
                                | '\\'
                                | '!'
                                | '@'
                                | '#'
                                | '$'
                                | '^'
                                | '&'
                                | '|'
                                | '<'
                                | '>'
                                | '['
                                | ']'
                                | ':'
                                | ';'
                        )
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::test_support::{InvocationBuilder, basic_credential};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub(super) fn provider(server: &MockServer) -> CloudbeesCiProvider {
        CloudbeesCiProvider::for_tests(
            CloudbeesCiProviderConfig {
                max_log_scan_bytes: logs::default_scan_limit(),
                controllers: BTreeMap::from([(
                    "team-ci".into(),
                    crate::CloudbeesCiControllerConfig {
                        base_url: format!("{}/team-ci/", server.uri()),
                        web_base_url: None,
                    },
                )]),
                egress_proxy: None,
                allowed_upstream_hosts: vec![format!("{}/team-ci/**", server.uri())],
            },
            ProviderLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn build_creates_stream_and_request_clients_per_controller() {
        let host = agent_access_provider::test_support::TestHost::default();
        let controller = |base: &str| crate::CloudbeesCiControllerConfig {
            base_url: base.into(),
            web_base_url: None,
        };
        CloudbeesCiProviderConfig {
            max_log_scan_bytes: logs::default_scan_limit(),
            controllers: BTreeMap::from([
                ("alpha".into(), controller("https://alpha.example/ci/")),
                ("beta".into(), controller("https://beta.example/")),
            ]),
            egress_proxy: None,
            allowed_upstream_hosts: vec![
                "https://alpha.example/ci/**".into(),
                "https://beta.example/**".into(),
            ],
        }
        .build(&host.context())
        .unwrap();
        let built = host
            .built_clients()
            .into_iter()
            .map(|client| (client.label, client.base.to_string(), client.profile))
            .collect::<Vec<_>>();
        let (alpha, beta) = (
            "providers.cloudbees_ci.controllers.alpha".to_string(),
            "providers.cloudbees_ci.controllers.beta".to_string(),
        );
        assert_eq!(
            built,
            [
                (
                    alpha.clone(),
                    "https://alpha.example/ci/".into(),
                    ClientProfile::Stream
                ),
                (
                    alpha,
                    "https://alpha.example/ci/".into(),
                    ClientProfile::Request
                ),
                (
                    beta.clone(),
                    "https://beta.example/".into(),
                    ClientProfile::Stream
                ),
                (beta, "https://beta.example/".into(), ClientProfile::Request),
            ]
        );
    }

    pub(super) fn invocation(action: &str, inputs: Value) -> ProviderInvocation {
        InvocationBuilder::new("cloudbees_ci", action)
            .inputs(inputs)
            .resources(BTreeMap::from([(
                "job".into(),
                vec!["team-ci/payments/build-api".into()],
            )]))
            .credential(basic_credential("automation", "secret"))
            .build()
    }

    #[test]
    fn location_must_remain_on_controller() {
        let base = Url::parse("https://ci.example/team-ci/").unwrap();
        let public = Url::parse("https://public.example/controller/").unwrap();
        assert_eq!(
            queue_id_from_location(&base, &base, "queue/item/42/"),
            Some(42)
        );
        assert_eq!(
            queue_id_from_location(&base, &base, "https://elsewhere/queue/item/42/"),
            None
        );
        assert_eq!(
            queue_id_from_location(&base, &base, "../queue/item/42/"),
            None
        );
        assert_eq!(
            queue_id_from_location(&base, &base, "queue/item/42/extra"),
            None
        );
        assert_eq!(
            queue_id_from_location(
                &base,
                &public,
                "https://public.example/controller/queue/item/42/"
            ),
            Some(42)
        );
        assert_eq!(
            queue_id_from_location(
                &base,
                &base,
                "https://ci.example/team-ci/queue/item/4294967296/"
            ),
            Some(4_294_967_296)
        );
        assert_eq!(
            queue_id_from_location(
                &base,
                &base,
                "https://ci.example/team-ci/queue/item/9223372036854775808/"
            ),
            None
        );
    }

    #[test]
    fn queue_location_checks_both_overlapping_roots() {
        let base = Url::parse("https://ci.example/").unwrap();
        let web = Url::parse("https://ci.example/jenkins/").unwrap();
        assert_eq!(
            queue_id_from_location(&base, &web, "https://ci.example/jenkins/queue/item/42/"),
            Some(42)
        );
        assert_eq!(
            queue_id_from_location(&base, &web, "/jenkins/queue/item/42/"),
            Some(42)
        );
        assert_eq!(
            queue_id_from_location(&base, &web, "/unlisted/queue/item/42/"),
            None
        );
    }

    #[tokio::test]
    async fn web_links_require_exact_item_path_on_configured_origin() {
        let server = MockServer::start().await;
        let mut ci = provider(&server);
        let controller = ci.controllers.get_mut("team-ci").unwrap();
        controller.web_base = Url::parse("https://public.example/controller/").unwrap();
        assert_eq!(
            CloudbeesCiProvider::verified_web_url(
                controller,
                Some("https://public.example/controller/job/payments/job/build-api/"),
                "payments/build-api",
                None,
            ),
            Some("https://public.example/controller/job/payments/job/build-api/".into())
        );
        assert_eq!(
            CloudbeesCiProvider::verified_web_url(
                controller,
                Some("https://public.example/controller/job/payments/job/other/"),
                "payments/build-api",
                None,
            ),
            None
        );
    }

    #[test]
    fn job_paths_and_namespaces_keep_controller_boundary() {
        assert!(is_cloudbees_ci_resource_path(
            "team-ci/payments/feature%2Ffoo",
            false
        ));
        for bad in [
            "team-ci",
            "team-ci/a?b",
            "team-ci/a#",
            "team-ci/ leading",
            "team-ci/../x",
        ] {
            assert!(!is_cloudbees_ci_resource_path(bad, false), "{bad}");
        }
        let base = Url::parse("https://ci.example/team-ci/").unwrap();
        assert!(
            CloudbeesCiProvider::job_url(&base, "payments/feature%2Ffoo")
                .as_str()
                .ends_with("/job/payments/job/feature%252Ffoo")
        );
        let selector = agent_access_provider::ResourceSelector::Namespace {
            value: "team-ci/payments".into(),
        };
        assert!(selector.matches("team-ci/payments/build-api"));
        assert!(!selector.matches("team-ci/payments"));
        assert!(!selector.matches("other-ci/payments/build-api"));
    }

    #[test]
    fn descriptor_declares_job_actions_download_io_and_basic_credentials() {
        let config = CloudbeesCiProviderConfig {
            max_log_scan_bytes: logs::default_scan_limit(),
            controllers: BTreeMap::from([(
                "team-ci".into(),
                crate::CloudbeesCiControllerConfig {
                    base_url: "https://ci.example/team-ci/".into(),
                    web_base_url: None,
                },
            )]),
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://ci.example/team-ci/**".into()],
        };
        let descriptor = cloudbees_ci_descriptor(&config);
        descriptor.validate().unwrap();
        assert_eq!(
            descriptor
                .actions
                .iter()
                .map(|action| action.action.as_str())
                .collect::<Vec<_>>(),
            [
                "job.view",
                "build.list",
                "build.view",
                "build.log.read",
                "build.artifact.list",
                "build.artifact.download",
                "build.tests.view",
                "queue.view",
                "build.trigger",
                "build.log.download",
                "build.pipeline.view",
                "build.pipeline.node.view",
                "build.pipeline.node.log.read",
                "build.pending-inputs.list",
                "build.tests.details",
                "build.tests.download",
            ]
        );
        for action in &descriptor.actions {
            assert_eq!(action.resource_scope.as_deref(), Some("job"));
            assert_eq!(
                action.lookup,
                agent_access_provider::LookupRequirement::None
            );
            assert_eq!(
                matches!(
                    action.io,
                    agent_access_provider::ActionIo::RawDownload { .. }
                ),
                action.action.ends_with(".download")
            );
        }
        assert_eq!(descriptor.credentials.service_kinds, ["basic_api_token"]);
        assert_eq!(
            descriptor.credential_profile_kind("cloudbees-ci-api-token"),
            Some("basic_api_token")
        );
    }

    #[tokio::test]
    async fn stalled_json_response_body_reports_upstream_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (headers_sent, headers_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 64\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let _ = headers_sent.send(());
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let limits = ProviderLimits {
            request_timeout_ms: 5_000,
            ..ProviderLimits::default()
        };
        let provider = CloudbeesCiProvider::for_tests(
            CloudbeesCiProviderConfig {
                max_log_scan_bytes: logs::default_scan_limit(),
                controllers: BTreeMap::from([(
                    "team-ci".into(),
                    crate::CloudbeesCiControllerConfig {
                        base_url: format!("{origin}/team-ci/"),
                        web_base_url: None,
                    },
                )]),
                egress_proxy: None,
                allowed_upstream_hosts: vec![format!("{origin}/team-ci/**")],
            },
            limits,
        )
        .unwrap();
        let request = tokio::spawn(async move {
            provider
                .invoke(invocation(
                    "job.view",
                    json!({"controller":"team-ci","job":"payments/build-api"}),
                ))
                .await
        });
        tokio::time::timeout(Duration::from_secs(10), headers_received)
            .await
            .unwrap()
            .unwrap();
        let error = request.await.unwrap().unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamTimeout);
        server.abort();
    }

    #[tokio::test]
    async fn queue_item_for_another_job_is_concealed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/team-ci/queue/item/42/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id":42, "task":{"fullName":"other/job"}, "why":"private queue detail"
            })))
            .mount(&server)
            .await;
        let result = provider(&server)
            .invoke(invocation(
                "queue.view",
                json!({"controller":"team-ci","job":"payments/build-api","queueId":42}),
            ))
            .await;
        assert!(matches!(
            result,
            Err(ref error) if error.reason_code() == ReasonCode::ScopeUnresolved
        ));
        assert_eq!(
            server.received_requests().await.unwrap()[0].url.path(),
            "/team-ci/queue/item/42/api/json"
        );
    }

    #[tokio::test]
    async fn queue_view_uses_controller_context_path() {
        let server = MockServer::start().await;
        let queue_id = 4_294_967_296_u64;
        Mock::given(method("GET"))
            .and(path("/team-ci/queue/item/4294967296/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id":queue_id,
                "task":{"fullName":"payments/build-api"},
                "executable":{"number":17},
                "why":"Waiting for an executor"
            })))
            .mount(&server)
            .await;
        let result = provider(&server)
            .invoke(invocation(
                "queue.view",
                json!({"controller":"team-ci","job":"payments/build-api","queueId":queue_id}),
            ))
            .await
            .unwrap();
        assert_eq!(result.result["queueId"], queue_id);
        assert_eq!(result.result["buildNumber"], 17);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url.path(),
            "/team-ci/queue/item/4294967296/api/json"
        );
    }

    #[tokio::test]
    async fn trigger_denies_parameterized_job_before_post() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fullName":"payments/build-api", "buildable":true,
                "property":[{"parameterDefinitions":[{"name":"SECRET","type":"PasswordParameterDefinition"}]}]
            })))
            .mount(&server)
            .await;
        let result = provider(&server)
            .invoke(invocation(
                "build.trigger",
                json!({"controller":"team-ci","job":"payments/build-api"}),
            ))
            .await;
        assert!(matches!(
            result,
            Err(ref error) if error.reason_code() == ReasonCode::VerificationMismatch
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn trigger_returns_validated_queue_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fullName":"payments/build-api", "buildable":true, "property":[]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/team-ci/job/payments/job/build-api/build"))
            .respond_with(ResponseTemplate::new(201).insert_header(
                "Location",
                format!("{}/team-ci/queue/item/42/", server.uri()),
            ))
            .mount(&server)
            .await;
        let result = provider(&server)
            .invoke(invocation(
                "build.trigger",
                json!({"controller":"team-ci","job":"payments/build-api"}),
            ))
            .await
            .unwrap();
        assert_eq!(result.result["queueId"], 42);
        assert_eq!(result.result["mutationStatus"], "applied");
    }

    #[tokio::test]
    async fn job_view_filters_inventory_secret_defaults_and_untrusted_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fullName":"payments/build-api", "_class":"com.cloudbees.hudson.plugins.folder.Folder",
                "url":"https://untrusted.example/job/payments/job/build-api/",
                "buildable":false, "jobs":[{"fullName":"payments/private"}],
                "property":[{"parameterDefinitions":[{"name":"PASSWORD","type":"PasswordParameterDefinition",
                    "defaultParameterValue":{"value":"secret-default"}}]}]
            })))
            .mount(&server)
            .await;
        let result = provider(&server)
            .invoke(invocation(
                "job.view",
                json!({"controller":"team-ci","job":"payments/build-api"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            result.result["kind"],
            "com.cloudbees.hudson.plugins.folder.Folder"
        );
        assert!(result.result.get("url").is_none());
        let text = result.result.to_string();
        assert!(!text.contains("payments/private"));
        assert!(!text.contains("secret-default"));
    }

    fn assert_upstream_rate_limited(error: &ProviderError, seconds: Option<u64>) {
        assert_eq!(error.decision(), agent_access_provider::Decision::Error);
        assert_eq!(error.reason_code(), ReasonCode::UpstreamRateLimited);
        let result = error.result.as_deref().unwrap();
        assert_eq!(result["limitScope"], "upstream");
        assert_eq!(result["service"], "cloudbees_ci");
        assert!(result.get("retrySafe").is_none());
        assert!(result.get("executionState").is_none());
        assert!(result.get("mutationStatus").is_none());
        match seconds {
            Some(seconds) => {
                assert_eq!(result["retryAfterSeconds"], seconds);
                assert_eq!(
                    error.message,
                    format!(
                        "cloudbees_ci is rate limiting requests. Retry after {seconds}s (at {}).",
                        result["retryAt"].as_str().unwrap()
                    )
                );
            }
            None => {
                assert!(result.get("retryAfterSeconds").is_none());
                assert!(result.get("retryAt").is_none());
                assert_eq!(
                    error.message,
                    "cloudbees_ci is rate limiting requests. Retry later."
                );
            }
        }
    }

    #[tokio::test]
    async fn controller_429_is_an_upstream_rate_limit_with_the_bounded_wait() {
        for (retry_after, seconds) in [
            (Some("25"), Some(25)),
            (Some("999999"), Some(86_400)),
            (None, None),
        ] {
            let server = MockServer::start().await;
            let mut template = ResponseTemplate::new(429).set_body_string("secret throttle page");
            if let Some(value) = retry_after {
                template = template.insert_header("Retry-After", value);
            }
            Mock::given(method("GET"))
                .and(path("/team-ci/job/payments/job/build-api/api/json"))
                .respond_with(template)
                .expect(1)
                .mount(&server)
                .await;
            let error = provider(&server)
                .invoke(invocation(
                    "job.view",
                    json!({"controller":"team-ci","job":"payments/build-api"}),
                ))
                .await
                .unwrap_err();
            assert_upstream_rate_limited(&error, seconds);
            assert!(!error.message.contains("secret"));
        }
    }

    #[tokio::test]
    async fn throttled_build_trigger_and_artifact_download_are_upstream_rate_limits() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fullName":"payments/build-api","buildable":true,"property":[]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/team-ci/job/payments/job/build-api/build"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "8"))
            .expect(1)
            .mount(&server)
            .await;
        mount_artifacts(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/team-ci/job/payments/job/build-api/42/artifact/reports/out.txt",
            ))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "3"))
            .expect(1)
            .mount(&server)
            .await;
        let ci = provider(&server);
        let trigger = ci
            .invoke(invocation(
                "build.trigger",
                json!({"controller":"team-ci","job":"payments/build-api"}),
            ))
            .await
            .unwrap_err();
        assert_upstream_rate_limited(&trigger, Some(8));
        let download = ci
            .invoke(invocation(
                "build.artifact.download",
                json!({
                    "controller":"team-ci","job":"payments/build-api","buildNumber":42,
                    "artifactPath":"reports/out.txt"
                }),
            ))
            .await
            .unwrap_err();
        assert_upstream_rate_limited(&download, Some(3));
    }

    async fn mount_artifacts(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/42/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "number":42,"artifacts":[
                    {"relativePath":"reports/out.txt","fileName":"out.txt"},
                    {"relativePath":"feature%2Ffoo.zip","fileName":"feature%2Ffoo.zip"}
                ]
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn artifact_list_and_download_use_exact_archived_path() {
        use futures_util::StreamExt;
        let server = MockServer::start().await;
        mount_artifacts(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/team-ci/job/payments/job/build-api/42/artifact/reports/out.txt",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/plain")
                    .set_body_bytes(b"artifact body".to_vec()),
            )
            .mount(&server)
            .await;
        let ci = provider(&server);
        let list = ci
            .invoke(invocation(
                "build.artifact.list",
                json!({
                    "controller":"team-ci","job":"payments/build-api","buildNumber":42
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            list.result["artifacts"][0]["artifactPath"],
            "reports/out.txt"
        );
        assert_eq!(
            list.result["artifacts"][1]["artifactPath"],
            "feature%2Ffoo.zip"
        );
        let result = ci
            .invoke(invocation(
                "build.artifact.download",
                json!({
                    "controller":"team-ci","job":"payments/build-api","buildNumber":42,
                    "artifactPath":"reports/out.txt"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(result.result["contentType"], "text/plain");
        let source = result.stream.unwrap().source;
        let agent_access_provider::ProviderResultStreamSource::Stream(source) = source else {
            panic!("expected stream")
        };
        let mut stream = source.lock().unwrap().take().unwrap();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(bytes, b"artifact body");
        let requests = server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .any(|r| r.url.path().ends_with("/artifact/reports/out.txt"))
        );
    }

    #[tokio::test]
    async fn artifact_download_rejects_unlisted_path_without_fetching_it() {
        let server = MockServer::start().await;
        mount_artifacts(&server).await;
        let error = provider(&server)
            .invoke(invocation(
                "build.artifact.download",
                json!({
                    "controller":"team-ci","job":"payments/build-api","buildNumber":42,
                    "artifactPath":"reports/other.txt"
                }),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ResourceNotFound);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        for path in [
            "../other.txt",
            "/reports/out.txt",
            "reports//out.txt",
            "reports\\out.txt",
        ] {
            let error = provider(&server)
                .local_scopes(
                    "build.artifact.download",
                    &json!({
                        "controller":"team-ci","job":"payments/build-api","buildNumber":42,
                        "artifactPath":path
                    }),
                )
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        }
    }

    #[tokio::test]
    async fn artifact_download_rejects_unlisted_redirect() {
        let server = MockServer::start().await;
        mount_artifacts(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/team-ci/job/payments/job/build-api/42/artifact/reports/out.txt",
            ))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "https://unlisted.example/secret"),
            )
            .mount(&server)
            .await;
        let error = provider(&server)
            .invoke(invocation(
                "build.artifact.download",
                json!({
                    "controller":"team-ci","job":"payments/build-api","buildNumber":42,
                    "artifactPath":"reports/out.txt"
                }),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    }

    #[tokio::test]
    async fn artifact_download_rejects_same_controller_redirect_outside_artifact_path() {
        let server = MockServer::start().await;
        mount_artifacts(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/team-ci/job/payments/job/build-api/42/artifact/reports/out.txt",
            ))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", "/team-ci/login"))
            .mount(&server)
            .await;
        let error = provider(&server)
            .invoke(invocation(
                "build.artifact.download",
                json!({
                    "controller":"team-ci","job":"payments/build-api","buildNumber":42,
                    "artifactPath":"reports/out.txt"
                }),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn artifact_download_authorizes_controller_hops_with_identity_encoding() {
        let server = MockServer::start().await;
        mount_artifacts(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/team-ci/job/payments/job/build-api/42/artifact/reports/out.txt",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"artifact".to_vec()))
            .mount(&server)
            .await;
        provider(&server)
            .invoke(invocation(
                "build.artifact.download",
                json!({
                    "controller":"team-ci","job":"payments/build-api","buildNumber":42,
                    "artifactPath":"reports/out.txt"
                }),
            ))
            .await
            .unwrap();
        let download = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.url.path().contains("/artifact/"))
            .unwrap();
        assert!(
            download.headers[reqwest::header::AUTHORIZATION.as_str()]
                .to_str()
                .unwrap()
                .starts_with("Basic ")
        );
        assert_eq!(download.headers["accept-encoding"], "identity");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn every_upstream_request_and_redirect_hop_is_traced() {
        let server = MockServer::start().await;
        mount_artifacts(&server).await;
        let artifact = "/team-ci/job/payments/job/build-api/42/artifact/reports/out.txt";
        Mock::given(method("GET"))
            .and(path(artifact))
            .respond_with(
                ResponseTemplate::new(302).insert_header("Location", format!("{artifact}/")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{artifact}/")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"artifact".to_vec()))
            .mount(&server)
            .await;
        let capture = agent_access_provider::test_support::install_trace_capture().start();
        let ci = provider(&server);
        capture
            .run(agent_access_provider::host::with_provider_context(
                agent_access_provider::CorrelationContext::for_tests(),
                "cloudbees_ci".into(),
                "build.artifact.download".into(),
                ci.invoke(invocation(
                    "build.artifact.download",
                    json!({
                        "controller":"team-ci","job":"payments/build-api","buildNumber":42,
                        "artifactPath":"reports/out.txt"
                    }),
                )),
            ))
            .await
            .unwrap();

        let events = capture.take_upstream_requests();
        // The artifact listing, then each hop of the download.
        let expected = [(200, 1), (302, 1), (200, 2)];
        assert_eq!(events.len(), expected.len(), "{events:?}");
        for (event, (status, attempt)) in events.iter().zip(expected) {
            assert_eq!(event["provider"], "cloudbees_ci");
            assert_eq!(event["action"], "build.artifact.download");
            assert_eq!(event["upstreamOperation"], "build.artifact.download");
            assert_eq!(event["http.statusCode"], status);
            assert_eq!(event["upstreamAttempt"], attempt);
        }
    }

    #[tokio::test]
    async fn artifact_download_enforces_content_length_cap() {
        let server = MockServer::start().await;
        mount_artifacts(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/team-ci/job/payments/job/build-api/42/artifact/reports/out.txt",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"1234567890".to_vec()))
            .mount(&server)
            .await;
        let mut ci = provider(&server);
        ci.download_limit = 4;
        let error = ci
            .invoke(invocation(
                "build.artifact.download",
                json!({
                    "controller":"team-ci","job":"payments/build-api","buildNumber":42,
                    "artifactPath":"reports/out.txt"
                }),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::AttachmentSizeDenied);
    }

    #[tokio::test]
    async fn missing_test_report_checks_build_existence() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/team-ci/job/payments/job/build-api/42/testReport/api/json",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/42/api/json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let error = provider(&server)
            .invoke(invocation(
                "build.tests.view",
                json!({
                    "controller":"team-ci","job":"payments/build-api","buildNumber":42
                }),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ResourceNotFound);
    }

    #[tokio::test]
    async fn missing_test_report_for_existing_build_is_not_a_missing_build() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/team-ci/job/payments/job/build-api/42/testReport/api/json",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/42/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"number":42})))
            .mount(&server)
            .await;
        let result = provider(&server)
            .invoke(invocation(
                "build.tests.view",
                json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42}),
            ))
            .await
            .unwrap();
        assert_eq!(result.result["reportAvailable"], false);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn build_list_rejects_more_than_requested_results() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fullName":"payments/build-api",
                "builds":[{"number":42},{"number":41}]
            })))
            .mount(&server)
            .await;
        let error = provider(&server)
            .invoke(invocation(
                "build.list",
                json!({"controller":"team-ci","job":"payments/build-api","maxResults":1}),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    }

    #[tokio::test]
    async fn build_list_omits_unverified_web_links() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fullName":"payments/build-api",
                "builds":[{"number":42,"url":"https://elsewhere.example/private/42/"}]
            })))
            .mount(&server)
            .await;
        let result = provider(&server)
            .invoke(invocation(
                "build.list",
                json!({"controller":"team-ci","job":"payments/build-api","maxResults":1}),
            ))
            .await
            .unwrap();
        assert_eq!(result.result["builds"][0]["number"], 42);
        assert!(
            !result.result["builds"][0]
                .as_object()
                .unwrap()
                .contains_key("url")
        );
    }

    #[tokio::test]
    async fn build_view_rejects_wrong_build_number() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/42/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"number":43})))
            .mount(&server)
            .await;
        let error = provider(&server)
            .invoke(invocation(
                "build.view",
                json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42}),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    }

    #[tokio::test]
    async fn trigger_post_404_is_not_reported_as_applied() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fullName":"payments/build-api","buildable":true,"property":[]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/team-ci/job/payments/job/build-api/build"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let error = provider(&server)
            .invoke(invocation(
                "build.trigger",
                json!({
                    "controller":"team-ci","job":"payments/build-api"
                }),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ResourceNotFound);
    }

    const JOB_API: &str = "/team-ci/job/payments/job/build-api/api/json";

    fn job_inputs(extra: Value) -> Value {
        let mut inputs = json!({"controller":"team-ci","job":"payments/build-api"});
        for (key, value) in extra.as_object().unwrap() {
            inputs[key] = value.clone();
        }
        inputs
    }

    fn input_category(error: &ProviderError) -> &str {
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{error:?}");
        error.result.as_deref().unwrap()["inputCategory"]
            .as_str()
            .unwrap()
    }

    fn provider_with_limits(origin: &str, limits: ProviderLimits) -> CloudbeesCiProvider {
        CloudbeesCiProvider::for_tests(
            CloudbeesCiProviderConfig {
                max_log_scan_bytes: logs::default_scan_limit(),
                controllers: BTreeMap::from([(
                    "team-ci".into(),
                    crate::CloudbeesCiControllerConfig {
                        base_url: format!("{origin}/team-ci/"),
                        web_base_url: None,
                    },
                )]),
                egress_proxy: None,
                allowed_upstream_hosts: vec![format!("{origin}/team-ci/**")],
            },
            limits,
        )
        .unwrap()
    }

    async fn mount_buildable_job(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(JOB_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fullName":"payments/build-api","buildable":true,"property":[]
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn build_selector_resolves_with_one_projected_job_read() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(JOB_API))
            .and(query_param(
                "tree",
                "fullName,_class,builds[number]{0,0},lastFailedBuild[number]",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob",
                "fullName":"payments/build-api","builds":[],"lastFailedBuild":{"number":41}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/41/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"number":41})))
            .expect(1)
            .mount(&server)
            .await;
        let result = provider(&server)
            .invoke(invocation(
                "build.view",
                job_inputs(json!({"buildSelector":"lastFailedBuild"})),
            ))
            .await
            .unwrap();
        assert_eq!(result.result["number"], 41);
        assert_eq!(result.result["buildNumber"], 41);
        assert_eq!(result.result["buildSelector"], "lastFailedBuild");
        assert_eq!(result.audit.unwrap()["buildSelector"], "lastFailedBuild");
        assert_eq!(result.object_ids.unwrap()["buildNumber"], 41);
        server.verify().await;
    }

    #[tokio::test]
    async fn selector_failures_never_read_a_build() {
        for (body, expected) in [
            (
                json!({"fullName":"payments/build-api","builds":[],"lastFailedBuild":null}),
                ReasonCode::ResourceNotFound,
            ),
            (
                json!({"fullName":"payments/build-api","builds":[]}),
                ReasonCode::ResourceNotFound,
            ),
            (
                json!({"fullName":"payments/Build-API","builds":[],"lastFailedBuild":{"number":4}}),
                ReasonCode::ScopeUnresolved,
            ),
            (
                json!({"fullName":"payments/build-api","builds":[],"lastFailedBuild":{"number":0}}),
                ReasonCode::UpstreamProtocolFailed,
            ),
            (
                json!({"fullName":"payments/build-api",
                    "_class":"org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject"}),
                ReasonCode::InputInvalid,
            ),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(JOB_API))
                .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
                .mount(&server)
                .await;
            let url = format!(
                "{}/team-ci/job/payments/job/build-api/lastFailedBuild/console",
                server.uri()
            );
            let error = provider(&server)
                .invoke(invocation("build.log.read", json!({"url":url})))
                .await
                .unwrap_err();
            assert_eq!(error.reason_code(), expected, "{body}");
            match expected {
                ReasonCode::ResourceNotFound => {
                    assert_eq!(error.message, "CloudBees CI job has no lastFailedBuild");
                    assert_eq!(error.result.unwrap()["buildSelector"], "lastFailedBuild");
                }
                ReasonCode::InputInvalid => {
                    assert_eq!(input_category(&error), "job_is_container");
                    assert_eq!(
                        error.result.unwrap()["kind"],
                        "org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject"
                    );
                }
                _ => {}
            }
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn selector_log_cursor_continues_with_the_resolved_build_number() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(JOB_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fullName":"payments/build-api","builds":[],"lastBuild":{"number":42}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/plain")
                    .set_body_bytes(vec![b'a'; 3000]),
            )
            .mount(&server)
            .await;
        let ci = provider(&server);
        let first = ci
            .invoke(invocation(
                "build.log.read",
                job_inputs(json!({"buildSelector":"lastBuild","mode":"head","maxBytes":1024})),
            ))
            .await
            .unwrap()
            .result;
        assert_eq!(first["buildNumber"], 42);
        assert_eq!(first["buildSelector"], "lastBuild");
        let next = ci
            .invoke(invocation(
                "build.log.read",
                job_inputs(json!({"buildNumber":42,"mode":"head","maxBytes":1024,
                    "cursor":first["nextCursor"]})),
            ))
            .await
            .unwrap()
            .result;
        assert_eq!(next["sourceStart"], 1024);
        assert!(next.get("buildSelector").is_none());
    }

    #[tokio::test]
    async fn url_locator_reads_through_the_configured_api_root() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/team-ci/job/payments/job/feature%252Ffoo/42/api/json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"number":42})))
            .expect(1)
            .mount(&server)
            .await;
        let mut ci = provider(&server);
        ci.controllers.get_mut("team-ci").unwrap().web_base =
            Url::parse("https://public.example/controller/").unwrap();
        let inputs = json!({
            "url":"https://public.example/controller/job/payments/job/feature%252Ffoo/42/console?x=1"
        });
        assert_eq!(
            ci.local_scopes("build.view", &inputs).unwrap()["job"],
            vec!["team-ci/payments/feature%2Ffoo"]
        );
        let result = ci.invoke(invocation("build.view", inputs)).await.unwrap();
        assert_eq!(result.result["controller"], "team-ci");
        assert_eq!(result.result["job"], "payments/feature%2Ffoo");
        assert_eq!(result.result["buildNumber"], 42);
        server.verify().await;
    }

    #[tokio::test]
    async fn build_list_on_a_container_is_an_input_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(JOB_API))
            .and(query_param(
                "tree",
                "fullName,_class,builds[number,url,result,building,timestamp,duration]{0,20}",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fullName":"payments/build-api",
                "_class":"com.cloudbees.hudson.plugins.folder.Folder"
            })))
            .mount(&server)
            .await;
        let error = provider(&server)
            .invoke(invocation("build.list", job_inputs(json!({}))))
            .await
            .unwrap_err();
        assert_eq!(input_category(&error), "job_is_container");
        let result = error.result.unwrap();
        assert_eq!(result["field"], "job");
        assert_eq!(result["kind"], "com.cloudbees.hudson.plugins.folder.Folder");
    }

    #[tokio::test]
    async fn numeric_build_404_on_a_container_is_explained_by_one_job_read() {
        for (action, extra) in [
            ("build.view", json!({})),
            ("build.tests.view", json!({})),
            ("build.artifact.list", json!({})),
            ("build.log.read", json!({})),
            ("build.log.download", json!({})),
            ("build.tests.download", json!({})),
            ("build.pipeline.view", json!({})),
            ("build.pipeline.node.view", json!({"nodeId":"6"})),
        ] {
            let server = MockServer::start().await;
            // Every other path is an unmatched wiremock 404.
            Mock::given(method("GET"))
                .and(path(JOB_API))
                .and(query_param("tree", "fullName,_class,builds[number]{0,0}"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "fullName":"payments/build-api",
                    "_class":"org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject"
                })))
                .expect(1)
                .mount(&server)
                .await;
            let mut inputs = job_inputs(extra);
            inputs["buildNumber"] = json!(42);
            let error = provider(&server)
                .invoke(invocation(action, inputs))
                .await
                .unwrap_err();
            assert_eq!(input_category(&error), "job_is_container", "{action}");
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn numeric_build_404_on_a_job_keeps_resource_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(JOB_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fullName":"payments/build-api","builds":[]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let error = provider(&server)
            .invoke(invocation(
                "build.view",
                job_inputs(json!({"buildNumber":42})),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ResourceNotFound);
        assert_eq!(error.message, "CloudBees CI object was not found");
        server.verify().await;
    }

    #[tokio::test]
    async fn not_found_job_shaped_like_url_segments_gets_a_hint() {
        let server = MockServer::start().await;
        let inputs = json!({"controller":"team-ci","job":"job/payments/job/build-api"});
        let error = provider(&server)
            .invoke(invocation("job.view", inputs))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ResourceNotFound);
        assert!(
            error
                .message
                .contains("job looks like Jenkins URL segments")
                && error.message.contains("pass payments/build-api"),
            "{}",
            error.message
        );
    }

    #[tokio::test]
    async fn not_found_job_repeating_its_controller_gets_a_hint() {
        let server = MockServer::start().await;
        let inputs = json!({"controller":"team-ci","job":"team-ci/payments/build-api"});
        let error = provider(&server)
            .invoke(invocation("job.view", inputs))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ResourceNotFound);
        assert!(
            error.message.contains("job repeats the controller alias"),
            "{}",
            error.message
        );
        assert!(error.message.contains("omit the leading \"team-ci/\""));
        // Job-level actions do not probe further.
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        // Other not-found jobs keep the plain message.
        let error = provider(&server)
            .invoke(invocation("job.view", job_inputs(json!({}))))
            .await
            .unwrap_err();
        assert_eq!(error.message, "CloudBees CI object was not found");
    }

    fn assert_trigger_unverified(error: &ProviderError) {
        assert_eq!(error.decision(), agent_access_provider::Decision::Error);
        assert_eq!(error.reason_code(), ReasonCode::MutationVerificationFailed);
        assert!(error.message.contains("Do not retry"), "{}", error.message);
        assert_eq!(
            error.result.as_deref(),
            Some(&json!({
                "mutationStatus":"applied_unverified","retrySafe":false,
                "verificationStage":"mutation_response",
                "safeLocators":{"controller":"team-ci","job":"payments/build-api"}
            }))
        );
    }

    #[tokio::test]
    async fn trigger_post_5xx_is_applied_unverified() {
        for status in [500, 502, 503] {
            let server = MockServer::start().await;
            mount_buildable_job(&server).await;
            Mock::given(method("POST"))
                .and(path("/team-ci/job/payments/job/build-api/build"))
                .respond_with(ResponseTemplate::new(status))
                .expect(1)
                .mount(&server)
                .await;
            let error = provider(&server)
                .invoke(invocation("build.trigger", job_inputs(json!({}))))
                .await
                .unwrap_err();
            assert_trigger_unverified(&error);
            assert_eq!(error.upstream_status, Some(status));
        }
    }

    #[tokio::test]
    async fn trigger_post_timeout_after_send_is_applied_unverified() {
        let server = MockServer::start().await;
        mount_buildable_job(&server).await;
        Mock::given(method("POST"))
            .and(path("/team-ci/job/payments/job/build-api/build"))
            .respond_with(ResponseTemplate::new(201).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let ci = provider_with_limits(
            &server.uri(),
            ProviderLimits {
                request_timeout_ms: 300,
                ..ProviderLimits::default()
            },
        );
        let error = ci
            .invoke(invocation("build.trigger", job_inputs(json!({}))))
            .await
            .unwrap_err();
        assert_trigger_unverified(&error);
        let requests = server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .any(|request| request.method.as_str() == "POST")
        );
    }

    /// Serves the trigger's job read, then either drops the connection after
    /// receiving the POST or refuses the POST connection outright.
    async fn raw_trigger_controller(
        close_after_post: bool,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn head(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
            }
            request
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            if !close_after_post {
                // Refuse every later connection: the POST is never sent.
                drop(listener);
                assert!(head(&mut socket).await.starts_with(b"GET "));
                let body = br#"{"fullName":"payments/build-api","buildable":true,"property":[]}"#;
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                socket.write_all(body).await.unwrap();
                return;
            }
            let body = br#"{"fullName":"payments/build-api","buildable":true,"property":[]}"#;
            loop {
                let request = head(&mut socket).await;
                if request.starts_with(b"POST ") {
                    // Received, then the connection drops without a response.
                    drop(socket);
                    return;
                }
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                socket.write_all(body).await.unwrap();
                drop(socket);
                socket = listener.accept().await.unwrap().0;
            }
        });
        (origin, task)
    }

    #[tokio::test]
    async fn trigger_connection_lost_after_send_is_applied_unverified() {
        let (origin, server) = raw_trigger_controller(true).await;
        let error = provider_with_limits(&origin, ProviderLimits::default())
            .invoke(invocation("build.trigger", job_inputs(json!({}))))
            .await
            .unwrap_err();
        assert_trigger_unverified(&error);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn trigger_post_proven_not_sent_stays_a_plain_connection_error() {
        let (origin, server) = raw_trigger_controller(false).await;
        let error = provider_with_limits(&origin, ProviderLimits::default())
            .invoke(invocation("build.trigger", job_inputs(json!({}))))
            .await
            .unwrap_err();
        server.await.unwrap();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamConnectionFailed);
        assert!(error.result.is_none());
    }

    #[tokio::test]
    async fn trigger_without_queue_location_returns_reusable_safe_locators() {
        let server = MockServer::start().await;
        mount_buildable_job(&server).await;
        Mock::given(method("POST"))
            .and(path("/team-ci/job/payments/job/build-api/build"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let result = provider(&server)
            .invoke(invocation("build.trigger", job_inputs(json!({}))))
            .await
            .unwrap()
            .result;
        assert_eq!(result["mutationStatus"], "applied_unverified");
        assert_eq!(
            result["safeLocators"],
            json!({"controller":"team-ci","job":"payments/build-api"})
        );
    }

    #[test]
    fn every_action_documents_locators_and_builds() {
        let descriptor = cloudbees_ci_service_descriptor();
        descriptor.validate().unwrap();
        for action in &descriptor.actions {
            let documentation = action.documentation.as_ref().unwrap();
            for key in ["locator", "job", "url", "build", "errors"] {
                assert!(documentation[key].is_string(), "{} {key}", action.action);
            }
            let schema = &action.input_schema;
            assert!(schema["properties"]["url"].is_object(), "{}", action.action);
            assert!(schema["oneOf"].is_array(), "{}", action.action);
            assert_eq!(
                schema["properties"].get("buildSelector").is_some(),
                action.action.starts_with("build.")
                    && !matches!(action.action.as_str(), "build.list" | "build.trigger"),
                "{}",
                action.action
            );
        }
    }
}
