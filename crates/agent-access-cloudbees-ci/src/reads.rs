//! Fixed, job-scoped Jenkins and Pipeline REST reads. Upstream links are never followed.
use super::*;

const ACTIONS: &[(&str, &str)] = &[
    (
        "build.log.download",
        "Download the available plain-text build console log",
    ),
    (
        "build.pipeline.view",
        "View Pipeline stages and execution status",
    ),
    ("build.pipeline.node.view", "View a Pipeline stage or step"),
    (
        "build.pipeline.node.log.read",
        "Read a bounded Pipeline step log",
    ),
    (
        "build.pending-inputs.list",
        "List pending Pipeline input prompts",
    ),
    ("build.tests.details", "View bounded detailed test results"),
    (
        "build.tests.download",
        "Download the detailed test report as JSON",
    ),
];
const CASE_FIELDS: &str = "name,className,status,duration,age,failedSince,errorDetails,errorStackTrace,skippedMessage,stdout,stderr";

pub(super) fn is_action(action: &str) -> bool {
    ACTIONS.iter().any(|(name, _)| *name == action)
}

pub(super) fn valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|b| b.is_ascii_digit())
        && !value.starts_with('0')
}

pub(super) fn descriptors() -> Vec<ActionDescriptor> {
    ACTIONS
        .iter()
        .map(|(name, description)| {
            let descriptor = ActionDescriptor::new(*name, *description, input::schema(name))
                .documentation(input::documentation(name))
                .read_only()
                .scope("job")
                .credential_modes(["service", "per_user"]);
            if name.ends_with(".download") {
                descriptor.raw_download()
            } else {
                descriptor
            }
        })
        .collect()
}

fn projected(value: &Value, fields: &[&str]) -> Result<Value, ProviderError> {
    let object = value.as_object().ok_or_else(protocol_error)?;
    let mut result = serde_json::Map::new();
    for field in fields {
        if let Some(value) = object.get(*field) {
            if value.is_array() || value.is_object() {
                return Err(protocol_error());
            }
            result.insert((*field).into(), value.clone());
        }
    }
    Ok(Value::Object(result))
}

fn node(value: &Value) -> Result<Value, ProviderError> {
    if !value
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(valid_node_id)
        || value.get("name").and_then(Value::as_str).is_none()
        || value.get("status").and_then(Value::as_str).is_none()
    {
        return Err(protocol_error());
    }
    let mut result = projected(
        value,
        &[
            "id",
            "name",
            "status",
            "startTimeMillis",
            "durationMillis",
            "pauseDurationMillis",
        ],
    )?;
    if let Some(error) = value.get("error").filter(|v| !v.is_null()) {
        result["error"] = projected(error, &["message", "type"])?;
    }
    if let Some(parents) = value.get("parentNodes") {
        let parents = parents.as_array().ok_or_else(protocol_error)?;
        if parents
            .iter()
            .any(|p| !p.as_str().is_some_and(valid_node_id))
        {
            return Err(protocol_error());
        }
        result["parentNodes"] = json!(parents);
    }
    Ok(result)
}

fn report_too_large() -> ProviderError {
    ProviderError::deny(
        ReasonCode::AttachmentSizeDenied,
        "CloudBees CI detailed test report exceeds the JSON read limit; use build.tests.download",
    )
    .with_result(json!({"downloadAction":"build.tests.download"}))
}

fn report_suites(data: &Value) -> Result<&Vec<Value>, ProviderError> {
    let object = data.as_object().ok_or_else(protocol_error)?;
    match object.get("suites") {
        Some(Value::Array(suites)) => Ok(suites),
        None => Err(ProviderError::deny(
            ReasonCode::ResponseFormatUnsupported,
            "Detailed test reads and downloads support JUnit reports with top-level suites; use build.tests.view for aggregated reports",
        )),
        _ => Err(protocol_error()),
    }
}

fn failed_case(case: &Value) -> bool {
    matches!(
        case.get("status").and_then(Value::as_str),
        Some("FAILED" | "REGRESSION")
    )
}

fn test_tree() -> String {
    format!(
        "totalCount,failCount,skipCount,passCount,duration,suites[name,duration,cases[{CASE_FIELDS}]]"
    )
}

impl CloudbeesCiProvider {
    pub(super) async fn invoke_read(
        &self,
        action: &str,
        input: &JobInput<'_>,
        controller: &Controller,
        credential: &ExecutionCredential,
        job_url: Url,
    ) -> Result<ProviderResult, ProviderError> {
        let number = input.build_number.expect("required");
        let build_url = Self::append(job_url, &[&number.to_string()]);
        if action.ends_with(".download") {
            let (url, content_type, filename) = if action == "build.log.download" {
                (
                    Self::append(build_url, &["consoleText"]),
                    "text/plain",
                    format!("build-{number}-console.log"),
                )
            } else {
                let report_url = Self::append(build_url, &["testReport", "api", "json"]);
                // Check shape without buffering the full report. Aggregate reports do not
                // expose top-level suites and cannot satisfy this download contract.
                let (shape, _) = self
                    .json(
                        controller,
                        credential,
                        Self::tree(report_url.clone(), "suites{0,0}"),
                    )
                    .await?;
                report_suites(&shape)?;
                (
                    Self::tree(report_url, &test_tree()),
                    "application/json",
                    format!("build-{number}-tests.json"),
                )
            };
            return self
                .read_download(
                    action,
                    input,
                    controller,
                    credential,
                    url,
                    content_type,
                    filename,
                )
                .await;
        }
        let url = match action {
            "build.pipeline.view" => Self::append(build_url, &["wfapi", "describe"]),
            "build.pending-inputs.list" => {
                Self::append(build_url, &["wfapi", "pendingInputActions"])
            }
            "build.pipeline.node.view" | "build.pipeline.node.log.read" => Self::append(
                build_url,
                &[
                    "execution",
                    "node",
                    input.node_id.expect("required"),
                    "wfapi",
                    if action.ends_with(".view") {
                        "describe"
                    } else {
                        "log"
                    },
                ],
            ),
            "build.tests.details" => Self::tree(
                Self::append(build_url, &["testReport", "api", "json"]),
                &test_tree(),
            ),
            _ => unreachable!("declared read action"),
        };
        let size_error = if action == "build.tests.details" {
            report_too_large
        } else {
            response_too_large
        };
        let (data, reply) = self.json_with_size_error(controller, credential, url, size_error).await.map_err(|error| {
            if error.reason_code() == ReasonCode::ResourceNotFound && action != "build.tests.details" {
                ProviderError::deny(ReasonCode::ResourceNotFound,
                    "Pipeline data is unavailable: the build/node may not exist or the Pipeline REST API plugin may be absent")
                    .with_upstream(error.upstream_status, None)
            } else { error }
        })?;
        let mut value = json!({"controller":input.controller,"job":input.job,"buildNumber":number});
        match action {
            "build.pipeline.view" => {
                // Jenkins getId() can be a timestamp for historical runs; it is not
                // necessarily the build number. The request path selects the run.
                if data.get("id").and_then(Value::as_str).is_none()
                    || data.get("status").and_then(Value::as_str).is_none()
                {
                    return Err(protocol_error());
                }
                value["pipeline"] = projected(
                    &data,
                    &[
                        "id",
                        "name",
                        "status",
                        "startTimeMillis",
                        "endTimeMillis",
                        "durationMillis",
                        "pauseDurationMillis",
                    ],
                )?;
                value["pipeline"]["stages"] = data
                    .get("stages")
                    .and_then(Value::as_array)
                    .ok_or_else(protocol_error)?
                    .iter()
                    .map(node)
                    .collect::<Result<Value, _>>()?;
            }
            "build.pipeline.node.view" => {
                if data.get("id").and_then(Value::as_str) != input.node_id {
                    return Err(protocol_error());
                }
                value["node"] = node(&data)?;
                if let Some(nodes) = data.get("stageFlowNodes") {
                    value["node"]["stageFlowNodes"] = nodes
                        .as_array()
                        .ok_or_else(protocol_error)?
                        .iter()
                        .map(node)
                        .collect::<Result<Value, _>>()?;
                }
            }
            "build.pipeline.node.log.read" => {
                if data.get("nodeId").and_then(Value::as_str) != input.node_id
                    || data.get("nodeStatus").and_then(Value::as_str).is_none()
                    || data.get("length").and_then(Value::as_u64).is_none()
                    || data.get("hasMore").and_then(Value::as_bool).is_none()
                {
                    return Err(protocol_error());
                }
                let text = match data.get("text") {
                    Some(Value::String(text)) => text.as_str(),
                    None | Some(Value::Null) if data["length"] == 0 && data["hasMore"] == false => {
                        ""
                    }
                    None | Some(Value::Null) => {
                        return Err(ProviderError::deny(
                            ReasonCode::ResourceNotFound,
                            "Pipeline node log text is unavailable; inspect stageFlowNodes with build.pipeline.node.view",
                        ));
                    }
                    _ => return Err(protocol_error()),
                };
                if text.len() as u64 > LOG_LIMIT {
                    return Err(ProviderError::domain(
                        &CLOUDBEES_CI_LOG_CHUNK_EXCEEDED,
                        "Pipeline node log exceeds the bounded read limit",
                    ));
                }
                value["log"] = projected(
                    &data,
                    &["nodeId", "nodeStatus", "length", "hasMore", "text"],
                )?;
                value["log"]["text"] = json!(text);
            }
            "build.pending-inputs.list" => {
                value["inputs"] = data
                    .as_array()
                    .ok_or_else(protocol_error)?
                    .iter()
                    .map(|item| {
                        if item.get("id").and_then(Value::as_str).is_none()
                            || item.get("message").and_then(Value::as_str).is_none()
                        {
                            return Err(protocol_error());
                        }
                        projected(item, &["id", "message"])
                    })
                    .collect::<Result<Value, _>>()?;
            }
            "build.tests.details" => {
                value["report"] = projected(
                    &data,
                    &[
                        "totalCount",
                        "failCount",
                        "skipCount",
                        "passCount",
                        "duration",
                    ],
                )?;
                let suites = report_suites(&data)?;
                let mut candidates = Vec::new();
                for suite in suites {
                    let name = suite
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or_else(protocol_error)?;
                    for case in suite
                        .get("cases")
                        .and_then(Value::as_array)
                        .ok_or_else(protocol_error)?
                    {
                        if case.get("name").and_then(Value::as_str).is_none() {
                            return Err(protocol_error());
                        }
                        candidates.push((name, case));
                    }
                }
                // Keep upstream order within each group, while making late failures
                // reachable even when the preview is smaller than the passing cases.
                candidates.sort_by_key(|(_, case)| !failed_case(case));
                let failed = candidates
                    .iter()
                    .filter(|(_, case)| failed_case(case))
                    .count();
                let cases = candidates
                    .iter()
                    .take(input.max_results as usize)
                    .map(|(name, case)| {
                        let mut case =
                            projected(case, &CASE_FIELDS.split(',').collect::<Vec<_>>())?;
                        case["suite"] = json!(name);
                        Ok(case)
                    })
                    .collect::<Result<Vec<_>, ProviderError>>()?;
                value["report"]["truncated"] = json!(candidates.len() > cases.len());
                value["report"]["returnedCount"] = json!(cases.len());
                value["report"]["returnedFailedCount"] = json!(failed.min(cases.len()));
                value["report"]["cases"] = json!(cases);
            }
            _ => unreachable!("declared read action"),
        }
        Ok(self.result(
            action,
            input,
            value,
            &reply,
            controller.client.egress_route(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_download(
        &self,
        action: &str,
        input: &JobInput<'_>,
        controller: &Controller,
        credential: &ExecutionCredential,
        url: Url,
        content_type: &str,
        filename: String,
    ) -> Result<ProviderResult, ProviderError> {
        let (username, token) = basic_material(credential)?;
        if url.origin() != controller.base.origin()
            || !url.path().starts_with(controller.base.path())
        {
            return Err(escaped_base());
        }
        let started = Instant::now();
        // Console and report endpoints have no off-controller storage redirect contract.
        let mut response = controller
            .download_client
            .get_following_redirects(
                url.clone(),
                RedirectRules::new(0, self.request_timeout, &|request| {
                    request.basic_auth(username, Some(token))
                })
                .with_vet(&|candidate| *candidate == url)
                .with_decorate(&|request| {
                    request.header(reqwest::header::ACCEPT_ENCODING, "identity")
                }),
                action,
            )
            .await
            .map_err(|error| {
                ProviderError::error(error.reason_code(), "CloudBees CI download request failed")
            })?;
        complete_upstream_trace(&mut response, None);
        match response.status() {
            StatusCode::UNAUTHORIZED => {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamUnauthorized,
                    "CloudBees CI rejected the credential",
                ));
            }
            StatusCode::FORBIDDEN => {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamForbidden,
                    "CloudBees CI denied download access",
                ));
            }
            StatusCode::NOT_FOUND => {
                return Err(upstream_not_found(
                    "CloudBees CI log or test report was not found",
                ));
            }
            StatusCode::TOO_MANY_REQUESTS => return Err(rate_limited(response.headers())),
            status if !status.is_success() => {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamFailed,
                    "CloudBees CI returned an unexpected download status",
                ));
            }
            status if status != StatusCode::OK => return Err(protocol_error()),
            _ => {}
        }
        let media_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim);
        if media_type != Some(content_type) {
            return Err(protocol_error());
        }
        let size = response.content_length();
        if size.is_some_and(|s| s > self.download_limit) {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "CloudBees CI download exceeds size limit",
            ));
        }
        let reply = Reply {
            status: response.status(),
            bytes: Vec::new(),
            content_type: None,
            location: None,
            duration_ms: started.elapsed().as_millis() as u64,
        };
        let mut result = self.result(
            action,
            input,
            json!({"controller":input.controller,"job":input.job,"buildNumber":input.build_number,
                "fileName":filename,"contentType":content_type,"size":size}),
            &reply,
            controller.download_client.egress_route(),
        );
        let cap = self.download_limit;
        let idle = self.download_idle_timeout;
        let source =
            stream::try_unfold((response, 0u64), move |(mut response, count)| async move {
                let chunk = tokio::time::timeout(idle, response.chunk())
                    .await
                    .map_err(|_| {
                        ProviderStreamError::new(
                            ReasonCode::UpstreamTimeout,
                            "CloudBees CI download stalled",
                        )
                    })?
                    .map_err(|error| {
                        ProviderStreamError::new(
                            if error.is_timeout() {
                                ReasonCode::UpstreamTimeout
                            } else {
                                ReasonCode::UpstreamConnectionFailed
                            },
                            "CloudBees CI download failed",
                        )
                    })?;
                let Some(chunk) = chunk else {
                    return Ok(None);
                };
                let next = count
                    .checked_add(chunk.len() as u64)
                    .filter(|n| *n <= cap)
                    .ok_or_else(|| {
                        ProviderStreamError::new(
                            ReasonCode::AttachmentSizeDenied,
                            "CloudBees CI download exceeds size limit",
                        )
                    })?;
                Ok(Some((chunk, (response, next))))
            });
        let mut stream = ProviderResultStream::from_stream(content_type, source);
        if let Some(size) = size {
            stream = stream.with_expected_size(
                size,
                "CloudBees CI download size did not match Content-Length",
            );
        }
        result.stream = Some(stream);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{invocation, provider};
    use futures_util::StreamExt;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn inputs() -> Value {
        json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42})
    }
    fn node_inputs() -> Value {
        let mut value = inputs();
        value["nodeId"] = json!("6");
        value
    }
    async fn bytes(result: ProviderResult) -> Vec<u8> {
        let agent_access_provider::ProviderResultStreamSource::Stream(source) =
            result.stream.unwrap().source
        else {
            panic!("expected stream")
        };
        let mut stream = source.lock().unwrap().take().unwrap();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend(chunk.unwrap());
        }
        bytes
    }

    #[tokio::test]
    async fn console_download_streams_past_json_limit_without_artifact_lookup() {
        let server = MockServer::start().await;
        let content = vec![b'x'; JSON_LIMIT as usize + 1];
        Mock::given(method("GET"))
            .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
            .and(header("accept-encoding", "identity"))
            .and(header("authorization", "Basic YXV0b21hdGlvbjpzZWNyZXQ="))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(content.clone())
                    .insert_header("content-type", "text/plain;charset=UTF-8"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let result = provider(&server)
            .invoke(invocation("build.log.download", inputs()))
            .await
            .unwrap();
        assert_eq!(result.result["fileName"], "build-42-console.log");
        assert_eq!(bytes(result).await, content);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn downloads_reject_redirects_html_and_oversize() {
        for response in [
            ResponseTemplate::new(302).insert_header("location", "/team-ci/secret"),
            ResponseTemplate::new(200)
                .set_body_string("login")
                .insert_header("content-type", "text/html"),
            ResponseTemplate::new(200)
                .set_body_string("too large")
                .insert_header("content-type", "text/plain"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/team-ci/job/payments/job/build-api/42/consoleText"))
                .respond_with(response)
                .mount(&server)
                .await;
            let mut ci = provider(&server);
            ci.download_limit = 2;
            assert!(
                ci.invoke(invocation("build.log.download", inputs()))
                    .await
                    .is_err()
            );
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn downloads_distinguish_upstream_failures_from_invalid_success_responses() {
        for action in ["build.log.download", "build.tests.download"] {
            for status in [429, 503, 204] {
                let server = MockServer::start().await;
                let endpoint = if action == "build.log.download" {
                    "consoleText"
                } else {
                    "testReport/api/json"
                };
                let endpoint = format!("/team-ci/job/payments/job/build-api/42/{endpoint}");
                if action == "build.tests.download" {
                    Mock::given(method("GET"))
                        .and(path(&endpoint))
                        .and(query_param("tree", "suites{0,0}"))
                        .respond_with(
                            ResponseTemplate::new(200).set_body_json(json!({"suites":[]})),
                        )
                        .with_priority(1)
                        .expect(1)
                        .mount(&server)
                        .await;
                }
                Mock::given(method("GET"))
                    .and(path(&endpoint))
                    .respond_with(ResponseTemplate::new(status).insert_header("Retry-After", "4"))
                    .expect(1)
                    .mount(&server)
                    .await;
                let error = provider(&server)
                    .invoke(invocation(action, inputs()))
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.reason_code(),
                    match status {
                        204 => ReasonCode::UpstreamProtocolFailed,
                        429 => ReasonCode::UpstreamRateLimited,
                        _ => ReasonCode::UpstreamFailed,
                    }
                );
                if status == 429 {
                    let result = error.result.as_deref().unwrap();
                    assert_eq!(result["limitScope"], "upstream");
                    assert_eq!(result["service"], "cloudbees_ci");
                    assert_eq!(result["retryAfterSeconds"], 4);
                } else {
                    assert!(error.result.is_none());
                }
            }
        }
    }

    #[tokio::test]
    async fn test_download_uses_only_fixed_report_projection() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/team-ci/job/payments/job/build-api/42/testReport/api/json",
            ))
            .and(query_param("tree", "suites{0,0}"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"suites":[]})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/team-ci/job/payments/job/build-api/42/testReport/api/json",
            ))
            .and(query_param("tree", test_tree()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"suites":[]})))
            .expect(1)
            .mount(&server)
            .await;
        let result = provider(&server)
            .invoke(invocation("build.tests.download", inputs()))
            .await
            .unwrap();
        assert_eq!(result.result["contentType"], "application/json");
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes(result).await).unwrap(),
            json!({"suites":[]})
        );
    }

    #[tokio::test]
    async fn pipeline_reads_drop_upstream_links_and_mutation_urls() {
        let server = MockServer::start().await;
        Mock::given(path("/team-ci/job/payments/job/build-api/42/wfapi/describe"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"42","name":"#42","status":"PAUSED_PENDING_INPUT",
                "_links":{"secret":"bad"},"stages":[{"id":"6","name":"Build","status":"SUCCESS","_links":{"secret":"bad"}}]})))
            .mount(&server).await;
        Mock::given(path("/team-ci/job/payments/job/build-api/42/wfapi/pendingInputActions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id":"approve","message":"Continue?","proceedUrl":"/secret","abortUrl":"/secret"}])))
            .mount(&server).await;
        let ci = provider(&server);
        let result = ci
            .invoke(invocation("build.pipeline.view", inputs()))
            .await
            .unwrap()
            .result;
        assert_eq!(result["pipeline"]["stages"][0]["id"], "6");
        assert!(!result.to_string().contains("secret"));
        let result = ci
            .invoke(invocation("build.pending-inputs.list", inputs()))
            .await
            .unwrap()
            .result;
        assert_eq!(
            result["inputs"],
            json!([{"id":"approve","message":"Continue?"}])
        );
    }

    #[tokio::test]
    async fn node_details_preserve_steps_and_error_but_require_identity() {
        for id in ["6", "7"] {
            let server = MockServer::start().await;
            Mock::given(path("/team-ci/job/payments/job/build-api/42/execution/node/6/wfapi/describe"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":id,"name":"stage","status":"FAILED",
                    "stageFlowNodes":[{"id":"8","name":"shell","status":"FAILED","parentNodes":["6"],"error":{"message":"exit 1","type":"AbortException","extra":"hidden"}}]})))
                .mount(&server).await;
            let result = provider(&server)
                .invoke(invocation("build.pipeline.node.view", node_inputs()))
                .await;
            if id == "6" {
                let result = result.unwrap().result;
                assert_eq!(
                    result["node"]["stageFlowNodes"][0]["error"],
                    json!({"message":"exit 1","type":"AbortException"})
                );
            } else {
                assert_eq!(
                    result.unwrap_err().reason_code(),
                    ReasonCode::UpstreamProtocolFailed
                );
            }
        }
    }

    #[tokio::test]
    async fn node_logs_preserve_plugin_truncation_and_reject_oversize() {
        for length in [10, LOG_LIMIT as usize + 1] {
            let server = MockServer::start().await;
            Mock::given(path("/team-ci/job/payments/job/build-api/42/execution/node/6/wfapi/log"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"nodeId":"6","nodeStatus":"SUCCESS","length":length,"hasMore":true,"text":"x".repeat(length),"consoleUrl":"/secret"})))
                .mount(&server).await;
            let result = provider(&server)
                .invoke(invocation("build.pipeline.node.log.read", node_inputs()))
                .await;
            if length == 10 {
                let result = result.unwrap().result;
                assert_eq!(result["log"]["hasMore"], true);
                assert!(result["log"].get("consoleUrl").is_none());
            } else {
                let error = result.unwrap_err();
                assert_eq!(
                    error.reason_code(),
                    agent_access_provider::ProviderReason::from(&CLOUDBEES_CI_LOG_CHUNK_EXCEEDED)
                );
                assert_eq!(error.decision(), agent_access_provider::Decision::Deny);
                assert_eq!(error.reason_code().http_status(), 413);
            }
        }
    }

    #[tokio::test]
    async fn detailed_tests_bound_cases_and_project_diagnostics() {
        let server = MockServer::start().await;
        Mock::given(path("/team-ci/job/payments/job/build-api/42/testReport/api/json"))
            .and(query_param("tree",test_tree()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"totalCount":2,"suites":[{"name":"suite","cases":[
                {"name":"failed","status":"FAILED","errorDetails":"oops","errorStackTrace":"trace","stdout":"out","stderr":"err","secret":"hidden"},{"name":"passed"}]}]})))
            .mount(&server).await;
        let mut input = inputs();
        input["maxResults"] = json!(1);
        let result = provider(&server)
            .invoke(invocation("build.tests.details", input))
            .await
            .unwrap()
            .result;
        assert_eq!(result["report"]["cases"].as_array().unwrap().len(), 1);
        assert_eq!(result["report"]["cases"][0]["errorStackTrace"], "trace");
        assert_eq!(result["report"]["truncated"], true);
        assert!(!result.to_string().contains("hidden"));
    }

    #[tokio::test]
    async fn new_reads_validate_before_request_and_keep_job_scope() {
        let server = MockServer::start().await;
        let ci = provider(&server);
        for id in ["../secret", "%2f", "0", "123456789012345678901", ""] {
            let mut input = node_inputs();
            input["nodeId"] = json!(id);
            assert!(ci.local_scopes("build.pipeline.node.view", &input).is_err());
        }
        for (action, _) in ACTIONS {
            let input = if action.starts_with("build.pipeline.node.") {
                node_inputs()
            } else {
                inputs()
            };
            assert_eq!(
                ci.local_scopes(action, &input).unwrap()["job"],
                vec!["team-ci/payments/build-api"]
            );
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn unknown_length_download_enforces_stream_cap_and_idle_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for mode in ["success", "oversize", "stall"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                }
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
                if mode == "stall" {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                } else {
                    socket.write_all(b"4\r\nbody\r\n0\r\n\r\n").await.unwrap();
                }
            });
            let ci = CloudbeesCiProvider::for_tests(
                CloudbeesCiProviderConfig {
                    max_log_scan_bytes: logs::default_scan_limit(),
                    controllers: BTreeMap::from([(
                        "team-ci".into(),
                        CloudbeesCiControllerConfig {
                            base_url: format!("{origin}/team-ci/"),
                            web_base_url: None,
                        },
                    )]),
                    egress_proxy: None,
                    allowed_upstream_hosts: vec![format!("{origin}/team-ci/**")],
                },
                ProviderLimits::default()
                    .with_max_download_bytes(if mode == "oversize" { 2 } else { 10 })
                    .with_streaming_idle_timeout_ms(100),
            )
            .unwrap();
            let result = ci
                .invoke(invocation("build.log.download", inputs()))
                .await
                .unwrap();
            assert!(result.result["size"].is_null());
            let agent_access_provider::ProviderResultStreamSource::Stream(source) =
                result.stream.unwrap().source
            else {
                panic!("expected stream")
            };
            let mut stream = source.lock().unwrap().take().unwrap();
            let chunk = stream.next().await.unwrap();
            match mode {
                "success" => {
                    assert_eq!(chunk.unwrap().as_ref(), b"body");
                    assert!(stream.next().await.is_none());
                }
                "oversize" => assert_eq!(
                    chunk.unwrap_err().reason_code,
                    ReasonCode::AttachmentSizeDenied
                ),
                _ => assert_eq!(chunk.unwrap_err().reason_code, ReasonCode::UpstreamTimeout),
            }
            server.abort();
        }
    }
    #[tokio::test]
    async fn node_without_log_returns_empty_text_but_keeps_identity_validation() {
        for (id, text, expected) in [
            ("6", None, true),
            ("6", Some(Value::Null), true),
            ("7", None, false),
            ("6", Some(json!({})), false),
        ] {
            let server = MockServer::start().await;
            let mut response =
                json!({"nodeId":id,"nodeStatus":"SUCCESS","length":0,"hasMore":false});
            if let Some(text) = text {
                response["text"] = text;
            }
            Mock::given(path(
                "/team-ci/job/payments/job/build-api/42/execution/node/6/wfapi/log",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
            let result = provider(&server)
                .invoke(invocation("build.pipeline.node.log.read", node_inputs()))
                .await;
            if expected {
                let result = result.unwrap().result;
                assert_eq!(result["log"]["text"], "");
                assert_eq!(result["log"]["length"], 0);
                assert_eq!(result["log"]["hasMore"], false);
            } else {
                assert_eq!(
                    result.unwrap_err().reason_code(),
                    ReasonCode::UpstreamProtocolFailed
                );
            }
        }
    }

    #[tokio::test]
    async fn detailed_tests_prioritize_late_failures_and_regressions() {
        let server = MockServer::start().await;
        Mock::given(path("/team-ci/job/payments/job/build-api/42/testReport/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"suites":[
                {"name":"first","cases":[{"name":"passed","status":"PASSED"},{"name":"skipped","status":"SKIPPED"}]},
                {"name":"second","cases":[{"name":"failed","status":"FAILED"},{"name":"regressed","status":"REGRESSION"},{"name":"fixed","status":"FIXED"}]}
            ]}))).mount(&server).await;
        let mut input = inputs();
        input["maxResults"] = json!(2);
        let result = provider(&server)
            .invoke(invocation("build.tests.details", input))
            .await
            .unwrap()
            .result;
        assert_eq!(result["report"]["cases"][0]["name"], "failed");
        assert_eq!(result["report"]["cases"][1]["name"], "regressed");
        assert_eq!(result["report"]["returnedCount"], 2);
        assert_eq!(result["report"]["returnedFailedCount"], 2);
        assert_eq!(result["report"]["truncated"], true);
    }

    #[tokio::test]
    async fn aggregate_reports_are_explicitly_unsupported_before_download() {
        for action in ["build.tests.details", "build.tests.download"] {
            let server = MockServer::start().await;
            Mock::given(path(
                "/team-ci/job/payments/job/build-api/42/testReport/api/json",
            ))
            .and(query_param(
                "tree",
                if action.ends_with("download") {
                    "suites{0,0}".into()
                } else {
                    test_tree()
                },
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"_class":"hudson.tasks.test.AggregatedTestResultAction","totalCount":5}),
            ))
            .expect(1)
            .mount(&server)
            .await;
            let error = provider(&server)
                .invoke(invocation(action, inputs()))
                .await
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::ResponseFormatUnsupported);
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn oversized_test_preview_returns_size_denial_with_download_hint() {
        let server = MockServer::start().await;
        Mock::given(path("/team-ci/job/payments/job/build-api/42/testReport/api/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"suites":[{"name":"suite","cases":[{"name":"test","stdout":"x".repeat(JSON_LIMIT as usize)}]}]})))
            .mount(&server).await;
        let error = provider(&server)
            .invoke(invocation("build.tests.details", inputs()))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::AttachmentSizeDenied);
        assert_eq!(
            error.result.unwrap()["downloadAction"],
            "build.tests.download"
        );
    }
}
