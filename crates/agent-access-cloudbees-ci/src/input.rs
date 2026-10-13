//! Action inputs: the canonical `controller`/`job` locator, the `url`
//! alternative, build selection, field-specific input errors, and the input
//! schemas and documentation that describe them. URLs are parsed only, never
//! fetched; the derived scope is authorized like explicit inputs.
use super::*;
use agent_access_provider::ResourceSelector;

/// Jenkins permalinks accepted as `buildSelector` and in URLs.
pub(crate) const BUILD_SELECTORS: [&str; 7] = [
    "lastBuild",
    "lastCompletedBuild",
    "lastFailedBuild",
    "lastSuccessfulBuild",
    "lastStableBuild",
    "lastUnstableBuild",
    "lastUnsuccessfulBuild",
];

#[derive(Debug)]
pub(crate) struct JobInput<'a> {
    pub(crate) controller: String,
    pub(crate) job: String,
    /// The requested or, for a selector, resolved build number.
    pub(crate) build_number: Option<u64>,
    pub(crate) build_selector: Option<&'static str>,
    pub(crate) queue_id: Option<u64>,
    pub(crate) max_results: u64,
    pub(crate) log: Option<logs::LogInput<'a>>,
    pub(crate) artifact_path: Option<&'a str>,
    pub(crate) node_id: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlBuild {
    Number(u64),
    Selector(&'static str),
}

#[derive(Debug, PartialEq, Eq)]
struct Locator {
    controller: String,
    job: String,
    build: Option<UrlBuild>,
}

struct Shape {
    /// Build-level actions take exactly one of `buildNumber`,
    /// `buildSelector`, or a build in `url`.
    build: bool,
    extra: &'static [&'static str],
}

fn shape(action: &str) -> Option<Shape> {
    let (build, extra): (bool, &'static [&'static str]) = match action {
        "job.view" | "build.trigger" => (false, &[]),
        "build.list" => (false, &["maxResults"]),
        "queue.view" => (false, &["queueId"]),
        "build.view"
        | "build.tests.view"
        | "build.artifact.list"
        | "build.log.download"
        | "build.tests.download"
        | "build.pipeline.view"
        | "build.pending-inputs.list" => (true, &[]),
        "build.tests.details" => (true, &["maxResults"]),
        "build.pipeline.node.view" | "build.pipeline.node.log.read" => (true, &["nodeId"]),
        "build.artifact.download" => (true, &["artifactPath"]),
        "build.log.read" => (true, &["mode", "maxBytes", "cursor", "query", "maxMatches"]),
        _ => return None,
    };
    Some(Shape { build, extra })
}

impl Shape {
    fn accepted(&self) -> Vec<&'static str> {
        let mut fields = vec!["controller", "job", "url"];
        if self.build {
            fields.extend(["buildNumber", "buildSelector"]);
        }
        fields.extend(self.extra);
        fields
    }
}

/// An `input_invalid` denial naming the mistaken field. `result.inputCategory`
/// is a closed set documented in the provider docs.
pub(crate) fn input_error(
    category: &'static str,
    field: Option<&str>,
    message: impl Into<String>,
) -> ProviderError {
    let mut result = json!({ "inputCategory": category });
    if let Some(field) = field {
        result["field"] = json!(field);
    }
    ProviderError::deny(ReasonCode::InputInvalid, message).with_result(result)
}

/// A folder or multibranch project addressed where a job with builds is needed.
pub(crate) fn job_is_container(data: &Value) -> ProviderError {
    let mut error = input_error(
        "job_is_container",
        Some("job"),
        "job is a folder or multibranch project, which has no builds; use a job inside it, such as folder/job or multibranch-project/branch",
    );
    if let Some(kind) = data.get("_class").and_then(Value::as_str).filter(|kind| {
        kind.len() <= 256
            && kind
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '$'))
    }) && let Some(result) = error.result.as_deref_mut()
    {
        result["kind"] = json!(kind);
    }
    error
}

fn shown_key(key: &str) -> Option<&str> {
    (key.len() <= 64 && key.chars().all(|c| c.is_ascii_graphic())).then_some(key)
}

fn required_positive(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
    max: u64,
    hint: &str,
) -> Result<u64, ProviderError> {
    let value = object.get(field).ok_or_else(|| {
        input_error(
            "field_missing",
            Some(field),
            format!("{field} is required; {hint}"),
        )
    })?;
    value
        .as_u64()
        .filter(|n| (1..=max).contains(n))
        .ok_or_else(|| {
            input_error(
                "value_invalid",
                Some(field),
                format!("{field} must be a positive integer up to {max}; {hint}"),
            )
        })
}

fn build_number(value: &Value) -> Result<u64, ProviderError> {
    if let Some(number) = value
        .as_u64()
        .filter(|n| (1..=u64::from(u32::MAX)).contains(n))
    {
        return Ok(number);
    }
    let message = match value.as_str() {
        Some(text) if BUILD_SELECTORS.contains(&text) => {
            format!("buildNumber must be a positive integer; pass {text} as buildSelector")
        }
        Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            "buildNumber must be a JSON integer, not a string".to_owned()
        }
        _ => format!(
            "buildNumber must be a positive integer up to {}; use buildSelector for permalinks such as lastFailedBuild",
            u32::MAX
        ),
    };
    Err(input_error("value_invalid", Some("buildNumber"), message))
}

fn build_selector(value: &Value) -> Result<&'static str, ProviderError> {
    if let Some(selector) = value.as_str().and_then(|text| {
        BUILD_SELECTORS
            .into_iter()
            .find(|candidate| *candidate == text)
    }) {
        return Ok(selector);
    }
    let message = if value.is_u64() {
        "buildSelector is a Jenkins permalink name; pass a numeric build as buildNumber".to_owned()
    } else {
        format!(
            "buildSelector must be one of {}",
            BUILD_SELECTORS.join(", ")
        )
    };
    Err(input_error("value_invalid", Some("buildSelector"), message))
}

fn build_input(
    object: &serde_json::Map<String, Value>,
    from_url: Option<UrlBuild>,
) -> Result<(Option<u64>, Option<&'static str>), ProviderError> {
    let number = object.get("buildNumber").map(build_number).transpose()?;
    let selector = object
        .get("buildSelector")
        .map(build_selector)
        .transpose()?;
    if number.is_some() && selector.is_some() {
        return Err(input_error(
            "build_conflict",
            Some("buildSelector"),
            "pass buildNumber or buildSelector, not both",
        ));
    }
    if from_url.is_some() && (number.is_some() || selector.is_some()) {
        return Err(input_error(
            "build_conflict",
            Some(if number.is_some() {
                "buildNumber"
            } else {
                "buildSelector"
            }),
            "url already names a build; omit buildNumber and buildSelector, or pass a job url",
        ));
    }
    match (number, selector, from_url) {
        (Some(number), _, _) | (_, _, Some(UrlBuild::Number(number))) => Ok((Some(number), None)),
        (_, Some(selector), _) | (_, _, Some(UrlBuild::Selector(selector))) => {
            Ok((None, Some(selector)))
        }
        (None, None, None) => Err(input_error(
            "build_missing",
            Some("buildNumber"),
            "this action needs a build: pass buildNumber or buildSelector, or a build url",
        )),
    }
}

/// Checks an explicit `job` input and names the likely mistake.
fn check_job(job: &str) -> Result<(), ProviderError> {
    let invalid = |category, message: &str| Err(input_error(category, Some("job"), message));
    if job.contains("://") || job.starts_with("http:") || job.starts_with("https:") {
        return invalid(
            "job_is_url",
            "job must be the Jenkins full name below the controller, not a URL; pass the URL as url instead of controller and job",
        );
    }
    let segments = job.split('/').collect::<Vec<_>>();
    if segments.iter().any(|segment| segment.is_empty()) {
        return invalid(
            "job_invalid",
            "job must be Jenkins item names separated by \"/\", with no leading, trailing, or repeated \"/\" (for example payments/build-api)",
        );
    }
    if segments.iter().any(|segment| segment.trim() != *segment) {
        return invalid(
            "job_invalid",
            "job item names must not start or end with whitespace; use the name from the job URL path, not the display name",
        );
    }
    if !is_cloudbees_ci_resource_path(&format!("probe/{job}"), false) {
        return invalid(
            "job_invalid",
            "job contains \".\" or \"..\" segments, control characters, or a character Jenkins item names cannot use (?*\\!@#$^&|<>[]:;)",
        );
    }
    Ok(())
}

/// Whether a full name has the `job/<name>/job/<name>` shape of a Jenkins URL
/// path. Valid when a folder is named `job`, so callers use it only for hints.
pub(crate) fn has_url_job_segments(job: &str) -> bool {
    let segments = job.split('/').collect::<Vec<_>>();
    segments.len().is_multiple_of(2) && segments.iter().step_by(2).all(|segment| *segment == "job")
}

/// Decodes one percent-encoded path segment exactly once as strict UTF-8.
fn decode_once(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = char::from(*bytes.get(index + 1)?).to_digit(16)?;
            let low = char::from(*bytes.get(index + 2)?).to_digit(16)?;
            decoded.push((high * 16 + low) as u8);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn url_error(category: &'static str, message: &str) -> ProviderError {
    input_error(category, Some("url"), message)
}

fn root_segments(root: &Url) -> Vec<&str> {
    let mut segments = root
        .path_segments()
        .map(Iterator::collect::<Vec<_>>)
        .unwrap_or_default();
    if segments.last() == Some(&"") {
        segments.pop();
    }
    segments
}

impl CloudbeesCiProvider {
    fn check_controller(&self, controller: &str) -> Result<(), ProviderError> {
        if self.controllers.contains_key(controller) {
            return Ok(());
        }
        let (category, message) = if controller.contains("://") {
            (
                "controller_not_alias",
                "controller must be a configured alias, not a URL; pass the URL as url instead of controller and job",
            )
        } else if controller.contains('/') {
            (
                "controller_not_alias",
                "controller must be only the alias, the first segment of a cloudbees_ci_job resource value; pass the remaining segments as job",
            )
        } else if controller.contains('.') || controller.contains(':') {
            (
                "controller_not_alias",
                "controller must be a configured alias, not a host name; use the controller from resources_list inputs or coverage, or pass the job url",
            )
        } else {
            (
                "controller_not_configured",
                "controller is not a configured CloudBees CI controller alias; use the controller from resources_list inputs or coverage, or pass the job url",
            )
        };
        Err(input_error(category, Some("controller"), message))
    }

    /// Maps a Jenkins job or build URL onto a configured controller root. The
    /// URL is never requested.
    fn parse_url(&self, raw: &str) -> Result<Locator, ProviderError> {
        let url = Url::parse(raw).map_err(|_| {
            url_error(
                "url_invalid",
                "url must be an absolute http or https Jenkins job or build URL",
            )
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(url_error(
                "url_invalid",
                "url must be an absolute http or https Jenkins job or build URL",
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(url_error("url_invalid", "url must not contain credentials"));
        }
        let segments = url
            .path_segments()
            .map(Iterator::collect::<Vec<_>>)
            .unwrap_or_default();
        // Longest segment-wise root match; identical roots on two aliases fail closed.
        let mut best: Option<(usize, &str)> = None;
        let mut ambiguous = false;
        for (alias, controller) in &self.controllers {
            for root in [&controller.base, &controller.web_base] {
                if root.origin() != url.origin() {
                    continue;
                }
                let prefix = root_segments(root);
                if !segments.starts_with(&prefix) {
                    continue;
                }
                match best {
                    Some((length, _)) if length > prefix.len() => {}
                    Some((length, current)) if length == prefix.len() => {
                        ambiguous |= current != alias;
                    }
                    _ => {
                        best = Some((prefix.len(), alias));
                        ambiguous = false;
                    }
                }
            }
        }
        let Some((root_length, alias)) = best else {
            return Err(url_error(
                "url_not_configured",
                "url is not under a configured CloudBees CI controller; pass controller and job instead",
            ));
        };
        if ambiguous {
            return Err(url_error(
                "url_ambiguous",
                "url matches more than one configured CloudBees CI controller; pass controller and job instead",
            ));
        }
        let mut rest = &segments[root_length..];
        if rest.last() == Some(&"") {
            rest = &rest[..rest.len() - 1];
        }
        match rest.first() {
            Some(&"blue") => {
                return Err(url_error(
                    "url_blue_ocean",
                    "Blue Ocean URLs are not supported; pass the classic job or build URL (…/job/<name>/…)",
                ));
            }
            Some(&"queue") => {
                return Err(url_error(
                    "url_queue_item",
                    "queue item URLs do not identify a job; pass the job url, or controller and job, together with queueId",
                ));
            }
            _ => {}
        }
        let mut names = Vec::new();
        let mut index = 0;
        while let Some(segment) = rest.get(index) {
            match *segment {
                "" => {
                    return Err(url_error(
                        "url_invalid",
                        "url has an empty path segment in its job path",
                    ));
                }
                "view" | "job" => {
                    let Some(name) = rest.get(index + 1).filter(|name| !name.is_empty()) else {
                        return Err(url_error(
                            "url_invalid",
                            "url has a job/ or view/ segment without a name",
                        ));
                    };
                    if *segment == "job" {
                        let name = decode_once(name).ok_or_else(|| {
                            url_error(
                                "url_invalid",
                                "url contains malformed percent-encoding in a job name",
                            )
                        })?;
                        if name.contains('/') {
                            return Err(url_error(
                                "url_invalid",
                                "a job name in the url decodes to a value containing \"/\"; Jenkins URLs encode each item name separately",
                            ));
                        }
                        names.push(name);
                    }
                    index += 2;
                }
                _ => break,
            }
        }
        if names.is_empty() {
            return Err(url_error(
                "url_no_job",
                "url does not name a job: expected …/job/<name>/ after the controller root",
            ));
        }
        let job = names.join("/");
        if !is_cloudbees_ci_resource_path(&format!("{alias}/{job}"), false) {
            return Err(url_error(
                "url_invalid",
                "a job name in the url is not a valid Jenkins item name",
            ));
        }
        let build = match rest.get(index) {
            Some(segment) if !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()) => {
                let number = segment
                    .parse::<u64>()
                    .ok()
                    .filter(|n| (1..=u64::from(u32::MAX)).contains(n) && !segment.starts_with('0'))
                    .ok_or_else(|| url_error("url_invalid", "url has an invalid build number"))?;
                Some(UrlBuild::Number(number))
            }
            Some(segment) if segment.contains('=') => {
                return Err(url_error(
                    "url_invalid",
                    "matrix configuration URLs are not supported",
                ));
            }
            Some(segment) => BUILD_SELECTORS
                .into_iter()
                .find(|selector| selector == segment)
                .map(UrlBuild::Selector),
            None => None,
        };
        Ok(Locator {
            controller: alias.to_owned(),
            job,
            build,
        })
    }

    fn locator(&self, object: &serde_json::Map<String, Value>) -> Result<Locator, ProviderError> {
        let controller = object.get("controller");
        let job = object.get("job");
        if let Some(url) = object.get("url") {
            if controller.is_some() || job.is_some() {
                return Err(input_error(
                    "locator_conflict",
                    Some("url"),
                    "pass either url or controller and job, not both",
                ));
            }
            let url = url
                .as_str()
                .ok_or_else(|| url_error("url_invalid", "url must be a string"))?;
            return self.parse_url(url);
        }
        let (controller, job) = match (controller, job) {
            (Some(controller), Some(job)) => (controller, job),
            (None, Some(_)) | (None, None) => {
                return Err(input_error(
                    "locator_missing",
                    Some("controller"),
                    "pass controller and job, or a job or build url",
                ));
            }
            (Some(_), None) => {
                return Err(input_error(
                    "locator_missing",
                    Some("job"),
                    "job is required with controller; or pass a job or build url instead",
                ));
            }
        };
        let controller = controller.as_str().ok_or_else(|| {
            input_error(
                "value_invalid",
                Some("controller"),
                "controller must be a string",
            )
        })?;
        self.check_controller(controller)?;
        let job = job
            .as_str()
            .ok_or_else(|| input_error("value_invalid", Some("job"), "job must be a string"))?;
        check_job(job)?;
        Ok(Locator {
            controller: controller.to_owned(),
            job: job.to_owned(),
            build: None,
        })
    }

    pub(crate) fn parse<'a>(
        &self,
        action: &str,
        value: &'a Value,
    ) -> Result<JobInput<'a>, ProviderError> {
        let Some(shape) = shape(action) else {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "unknown action",
            ));
        };
        let object = value
            .as_object()
            .ok_or_else(|| input_error("value_invalid", None, "inputs must be a JSON object"))?;
        let accepted = shape.accepted();
        if let Some(key) = object.keys().find(|key| !accepted.contains(&key.as_str())) {
            let accepted = accepted.join(", ");
            return Err(match shown_key(key) {
                Some(key) => input_error(
                    "unknown_field",
                    Some(key),
                    format!("unknown input {key} for {action}; accepted inputs: {accepted}"),
                ),
                None => input_error(
                    "unknown_field",
                    None,
                    format!("unknown input for {action}; accepted inputs: {accepted}"),
                ),
            });
        }
        let locator = self.locator(object)?;
        // Job-level actions ignore a build named by the URL.
        let (build_number, build_selector) = if shape.build {
            build_input(object, locator.build)?
        } else {
            (None, None)
        };
        let queue_id = shape
            .extra
            .contains(&"queueId")
            .then(|| {
                required_positive(
                    object,
                    "queueId",
                    i64::MAX as u64,
                    "use the queueId returned by build.trigger",
                )
            })
            .transpose()?;
        let max_results = if shape.extra.contains(&"maxResults") {
            let max = if action == "build.tests.details" {
                100
            } else {
                50
            };
            match object.get("maxResults") {
                None => 20,
                Some(value) => value
                    .as_u64()
                    .filter(|n| (1..=max).contains(n))
                    .ok_or_else(|| {
                        input_error(
                            "value_invalid",
                            Some("maxResults"),
                            format!("maxResults must be an integer from 1 to {max}"),
                        )
                    })?,
            }
        } else {
            20
        };
        let artifact_path = shape
            .extra
            .contains(&"artifactPath")
            .then(|| {
                let path = object.get("artifactPath").ok_or_else(|| {
                    input_error(
                        "field_missing",
                        Some("artifactPath"),
                        "artifactPath is required; use an artifactPath from build.artifact.list",
                    )
                })?;
                path.as_str().filter(|path| valid_artifact_path(path)).ok_or_else(|| {
                    input_error(
                        "value_invalid",
                        Some("artifactPath"),
                        "artifactPath must be a relative path from build.artifact.list, without empty, \".\", or \"..\" segments, backslashes, or control characters",
                    )
                })
            })
            .transpose()?;
        let node_id = shape
            .extra
            .contains(&"nodeId")
            .then(|| {
                let node = object.get("nodeId").ok_or_else(|| {
                    input_error(
                        "field_missing",
                        Some("nodeId"),
                        "nodeId is required; use a stage or step id from build.pipeline.view or build.pipeline.node.view",
                    )
                })?;
                node.as_str().filter(|node| reads::valid_node_id(node)).ok_or_else(|| {
                    input_error(
                        "value_invalid",
                        Some("nodeId"),
                        "nodeId must be a decimal string such as \"7\" (a stage or step id from build.pipeline.view)",
                    )
                })
            })
            .transpose()?;
        let log = (action == "build.log.read")
            .then(|| logs::LogInput::parse(object))
            .transpose()?;
        if log.is_some() && object.contains_key("cursor") && build_selector.is_some() {
            return Err(input_error(
                "option_conflict",
                Some("cursor"),
                "a log cursor continues a numeric build; pass the buildNumber returned with nextCursor instead of buildSelector or a permalink url",
            ));
        }
        Ok(JobInput {
            controller: locator.controller,
            job: locator.job,
            build_number,
            build_selector,
            queue_id,
            max_results,
            log,
            artifact_path,
            node_id,
        })
    }
}

/// The action inputs addressing a `cloudbees_ci_job` selector: an exact job
/// splits at its first `/`; a namespace names its controller.
pub(crate) fn job_action_inputs(
    selector: &ResourceSelector,
) -> Option<serde_json::Map<String, Value>> {
    let mut inputs = serde_json::Map::new();
    match selector {
        ResourceSelector::Exact { value } => {
            let (controller, job) = value.split_once('/')?;
            inputs.insert("controller".into(), json!(controller));
            inputs.insert("job".into(), json!(job));
        }
        ResourceSelector::Namespace { value } => {
            let controller = value.split('/').next().filter(|alias| !alias.is_empty())?;
            inputs.insert("controller".into(), json!(controller));
        }
        ResourceSelector::All => return None,
    }
    Some(inputs)
}

/// The input schema of an action. Locator and build alternatives are
/// expressed with `oneOf`; extended grammar lives in [`documentation`].
pub(crate) fn schema(action: &str) -> Value {
    let shape = shape(action).expect("declared action");
    let mut properties = json!({
        "controller": {"type":"string","description":"Configured controller alias: the first segment of a cloudbees_ci_job resource value"},
        "job": {"type":"string","description":"Jenkins full name below the controller, such as folder/job; not a display name or URL"},
        "url": {"type":"string","description":"Jenkins job or build URL on a configured controller, instead of controller and job"},
    });
    let mut required = Vec::new();
    if shape.build {
        properties["buildNumber"] =
            json!({"type":"integer","minimum":1,"maximum":u32::MAX,"description":"Build number"});
        properties["buildSelector"] = json!({"type":"string","enum":BUILD_SELECTORS,"description":"Jenkins permalink, resolved to a build number"});
    }
    for field in shape.extra {
        match *field {
            "maxResults" => {
                let max = if action == "build.tests.details" {
                    100
                } else {
                    50
                };
                properties["maxResults"] = json!({"type":"integer","minimum":1,"maximum":max});
            }
            "queueId" => {
                properties["queueId"] = json!({"type":"integer","minimum":1,"maximum":i64::MAX});
                required.push("queueId");
            }
            "nodeId" => {
                properties["nodeId"] =
                    json!({"type":"string","pattern":"^[1-9][0-9]*$","minLength":1,"maxLength":20});
                required.push("nodeId");
            }
            "artifactPath" => {
                properties["artifactPath"] = json!({"type":"string","minLength":1});
                required.push("artifactPath");
            }
            _ => {}
        }
    }
    if action == "build.log.read" {
        properties
            .as_object_mut()
            .expect("properties")
            .extend(logs::input_properties());
    }
    // Each branch excludes the other locator's fields so mixed inputs fail
    // validation the same way runtime parsing rejects them.
    let one_of = if shape.build {
        json!([
            {"required":["controller","job"],"not":{"required":["url"]},
                "oneOf":[{"required":["buildNumber"]},{"required":["buildSelector"]}]},
            {"required":["url"],"not":{"anyOf":[{"required":["controller"]},{"required":["job"]},
                {"required":["buildNumber","buildSelector"]}]}}
        ])
    } else {
        json!([
            {"required":["controller","job"],"not":{"required":["url"]}},
            {"required":["url"],"not":{"anyOf":[{"required":["controller"]},{"required":["job"]}]}}
        ])
    };
    let mut schema = json!({
        "type":"object",
        "properties":properties,
        "oneOf":one_of,
        "additionalProperties":false
    });
    if !required.is_empty() {
        schema["required"] = json!(required);
    }
    if action == "build.log.read" {
        schema["allOf"] = json!([
            {"if":{"properties":{"mode":{"const":"search"}},"required":["mode"]},
                "then":{"required":["query"]},
                "else":{"not":{"anyOf":[{"required":["query"]},{"required":["maxMatches"]}]}}},
            {"if":{"required":["cursor"]},
                "then":{"required":["mode"],"properties":{"mode":{"enum":["head","search"]}}}},
            {"not":{"required":["cursor","buildSelector"]}}
        ]);
    }
    schema
}

/// Extended usage for an action, kept out of MCP `tools/list`.
pub(crate) fn documentation(action: &str) -> Value {
    let shape = shape(action).expect("declared action");
    let mut documentation = json!({
        "locator": "Pass url, or controller and job. resources_list shows controller and job as a resource's inputs, or the controller for a namespace or all grant under coverage; otherwise split a cloudbees_ci_job value at its first \"/\": team-ci/payments/build-api is controller team-ci, job payments/build-api. Do not guess aliases.",
        "job": "job is the Jenkins full name: item names from the URL path joined by \"/\", not display names. Folders and multibranch projects hold jobs; address a job inside them, such as folder/job or project/branch. A multibranch branch feature/foo is item feature%2Ffoo; pass it literally. A namespace grant covers jobs below a folder, not the folder item.",
        "url": "A classic Jenkins job or build URL under a configured controller's base_url or web_base_url, such as https://ci.example.com/team-ci/job/payments/job/build-api/42/console. view/<name> segments are skipped and each job name is percent-decoded once. Later path segments, query, and fragment are ignored. Blue Ocean, queue item, and non-controller URLs are rejected. The URL is never fetched; the derived controller and job are authorized like explicit inputs.",
        "errors": "Input mistakes return input_invalid with result.inputCategory and result.field naming the problem. A folder or multibranch project where a job is needed returns inputCategory job_is_container."
    });
    if shape.build {
        documentation["build"] = json!(format!(
            "Give exactly one of buildNumber, buildSelector, or a build url (…/42/ or …/lastFailedBuild/). buildSelector is one of {} and resolves to a number after authorization; results echo buildNumber and buildSelector. A job without that build returns resource_not_found.",
            BUILD_SELECTORS.join(", ")
        ));
    } else {
        documentation["build"] =
            json!("This action addresses the job; a build in the url is ignored.");
    }
    match action {
        "build.log.read" => {
            documentation["cursor"] = json!(
                "nextCursor is bound to the numeric build. Continue with the returned buildNumber, not buildSelector or a permalink url, and keep mode, query, and limits unchanged."
            );
        }
        "queue.view" => {
            documentation["queueId"] = json!(
                "Use the queueId returned by build.trigger. A queue URL does not identify a job; pass the job's url or controller and job with queueId."
            );
        }
        "build.trigger" => {
            documentation["receipt"] = json!(
                "A queue receipt reports mutationStatus applied. Without a usable queue location, or when the request may have reached the controller but no response confirmed it (timeout, connection failure, or 5xx), the result reports mutationStatus applied_unverified and retrySafe false; the uncertain case is the error mutation_verification_failed. safeLocators holds controller and job. Check job.view (inQueue, lastBuild) or build.list before triggering again."
            );
        }
        _ => {}
    }
    documentation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> CloudbeesCiProvider {
        let controller = |base: &str, web: Option<&str>| CloudbeesCiControllerConfig {
            base_url: base.into(),
            web_base_url: web.map(str::to_owned),
        };
        CloudbeesCiProvider::for_tests(
            CloudbeesCiProviderConfig {
                max_log_scan_bytes: logs::default_scan_limit(),
                controllers: BTreeMap::from([
                    (
                        "team-ci".into(),
                        controller(
                            "https://ci-api.example.com/team-ci/",
                            Some("https://ci.example.com/team-ci/"),
                        ),
                    ),
                    (
                        "nested".into(),
                        controller("https://ci.example.com/team-ci/job/nested-root/", None),
                    ),
                    ("root".into(), controller("https://root.example.com/", None)),
                    (
                        "twin-a".into(),
                        controller("https://twin.example.com/ci/", None),
                    ),
                    (
                        "twin-b".into(),
                        controller("https://twin.example.com/ci/", None),
                    ),
                ]),
                egress_proxy: None,
                allowed_upstream_hosts: vec![
                    "https://ci-api.example.com/**".into(),
                    "https://ci.example.com/**".into(),
                    "https://root.example.com/**".into(),
                    "https://twin.example.com/**".into(),
                ],
            },
            ProviderLimits::default(),
        )
        .unwrap()
    }

    fn category(error: &ProviderError) -> (&str, Option<&str>) {
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{error:?}");
        let result = error.result.as_deref().expect("input error result");
        (
            result["inputCategory"].as_str().unwrap(),
            result.get("field").and_then(Value::as_str),
        )
    }

    #[test]
    fn url_table_derives_controller_job_and_build() {
        let ci = provider();
        let number = |n| Some(UrlBuild::Number(n));
        let selector = |s| Some(UrlBuild::Selector(s));
        for (url, controller, job, build) in [
            // Job URL, web root, with and without trailing slash.
            (
                "https://ci.example.com/team-ci/job/payments/job/build-api/",
                "team-ci",
                "payments/build-api",
                None,
            ),
            (
                "https://ci.example.com/team-ci/job/payments/job/build-api",
                "team-ci",
                "payments/build-api",
                None,
            ),
            // API root (base_url) also matches.
            (
                "https://ci-api.example.com/team-ci/job/payments/job/build-api/42/api/json?tree=x",
                "team-ci",
                "payments/build-api",
                number(42),
            ),
            // Build URL with later segments, query and fragment ignored.
            (
                "https://ci.example.com/team-ci/job/payments/job/build-api/34/display/redirect?page=tests#x",
                "team-ci",
                "payments/build-api",
                number(34),
            ),
            (
                "https://ci.example.com/team-ci/job/payments/job/build-api/34/artifact/out/x.zip",
                "team-ci",
                "payments/build-api",
                number(34),
            ),
            (
                "https://ci.example.com/team-ci/job/payments/job/build-api/34/pipeline-console/?selected-node=17",
                "team-ci",
                "payments/build-api",
                number(34),
            ),
            // Permalinks become selectors.
            (
                "https://ci.example.com/team-ci/job/payments/job/build-api/lastFailedBuild/console",
                "team-ci",
                "payments/build-api",
                selector("lastFailedBuild"),
            ),
            (
                "https://ci.example.com/team-ci/job/a/lastSuccessfulBuild/",
                "team-ci",
                "a",
                selector("lastSuccessfulBuild"),
            ),
            // view/<name> pairs are skipped before and between job pairs.
            (
                "https://ci.example.com/team-ci/view/Team/job/payments/view/change-requests/job/PR-12/34/",
                "team-ci",
                "payments/PR-12",
                number(34),
            ),
            // Multibranch branch names decode exactly once.
            (
                "https://ci.example.com/team-ci/job/payments/job/build-api/job/feature%252Ffoo/17/",
                "team-ci",
                "payments/build-api/feature%2Ffoo",
                number(17),
            ),
            (
                "https://ci.example.com/team-ci/job/caf%C3%A9/",
                "team-ci",
                "café",
                None,
            ),
            // Job-level pages are ignored.
            (
                "https://ci.example.com/team-ci/job/payments/job/build-api/changes",
                "team-ci",
                "payments/build-api",
                None,
            ),
            // Longest root wins over the shorter web root.
            (
                "https://ci.example.com/team-ci/job/nested-root/job/app/5/",
                "nested",
                "app",
                number(5),
            ),
            // A root context path of "/".
            ("https://root.example.com/job/app/", "root", "app", None),
            // Host case and default port are normalized by the URL parser.
            (
                "HTTPS://CI.EXAMPLE.COM:443/team-ci/job/app/",
                "team-ci",
                "app",
                None,
            ),
        ] {
            let locator = ci.parse_url(url).unwrap_or_else(|e| panic!("{url}: {e:?}"));
            assert_eq!(
                locator,
                Locator {
                    controller: controller.into(),
                    job: job.into(),
                    build
                },
                "{url}"
            );
        }
    }

    #[test]
    fn url_rejections_are_specific_and_never_list_configuration() {
        let ci = provider();
        for (url, expected) in [
            ("not a url", "url_invalid"),
            ("ftp://ci.example.com/team-ci/job/a/", "url_invalid"),
            (
                "https://user:pw@ci.example.com/team-ci/job/a/",
                "url_invalid",
            ),
            (
                "https://other.example.com/team-ci/job/a/",
                "url_not_configured",
            ),
            ("http://ci.example.com/team-ci/job/a/", "url_not_configured"),
            (
                "https://ci.example.com:8443/team-ci/job/a/",
                "url_not_configured",
            ),
            // Segment-wise prefix: /team-ci-evil/ is not under /team-ci/.
            (
                "https://ci.example.com/team-ci-evil/job/a/",
                "url_not_configured",
            ),
            ("https://twin.example.com/ci/job/a/", "url_ambiguous"),
            ("https://ci.example.com/team-ci/", "url_no_job"),
            ("https://ci.example.com/team-ci/view/all/", "url_no_job"),
            (
                "https://ci.example.com/team-ci/computer/agent-1/",
                "url_no_job",
            ),
            (
                "https://ci.example.com/team-ci/blue/organizations/jenkins/payments%2Fbuild-api/detail/main/3/pipeline",
                "url_blue_ocean",
            ),
            (
                "https://ci.example.com/team-ci/queue/item/51/",
                "url_queue_item",
            ),
            ("https://ci.example.com/team-ci/job/a%zz/", "url_invalid"),
            ("https://ci.example.com/team-ci/job/a%2/", "url_invalid"),
            ("https://ci.example.com/team-ci/job/a%+5/", "url_invalid"),
            ("https://ci.example.com/team-ci/job/a%FF/", "url_invalid"),
            (
                "https://ci.example.com/team-ci/job/payments%2Fsecret/",
                "url_invalid",
            ),
            ("https://ci.example.com/team-ci/job/a/job/", "url_invalid"),
            (
                "https://ci.example.com/team-ci/job/a//job/b/",
                "url_invalid",
            ),
            ("https://ci.example.com/team-ci/job/a%3F/", "url_invalid"),
            ("https://ci.example.com/team-ci/job/a%09b/", "url_invalid"),
            (
                "https://ci.example.com/team-ci/job/a/label=linux/34/",
                "url_invalid",
            ),
            ("https://ci.example.com/team-ci/job/a/0/", "url_invalid"),
            ("https://ci.example.com/team-ci/job/a/042/", "url_invalid"),
            (
                "https://ci.example.com/team-ci/job/a/4294967296/",
                "url_invalid",
            ),
        ] {
            let error = ci.parse_url(url).unwrap_err();
            assert_eq!(category(&error), (expected, Some("url")), "{url}");
            for configured in ["team-ci", "nested", "twin-a", "twin-b", "example.com"] {
                assert!(
                    !error.message.contains(configured),
                    "{url}: {}",
                    error.message
                );
            }
        }
    }

    #[test]
    fn url_inputs_resolve_scopes_and_builds_like_explicit_inputs() {
        let ci = provider();
        let url = "https://ci.example.com/team-ci/job/payments/job/build-api/42/console";
        assert_eq!(
            ci.local_scopes("build.view", &json!({"url": url})).unwrap()["job"],
            vec!["team-ci/payments/build-api"]
        );
        let input_value = json!({"url": url});
        let input = ci.parse("build.view", &input_value).unwrap();
        assert_eq!(input.build_number, Some(42));
        // Job-level actions ignore the build part.
        for action in ["job.view", "build.list", "build.trigger"] {
            let input = ci.parse(action, &input_value).unwrap();
            assert_eq!((input.build_number, input.build_selector), (None, None));
        }
        let queue = json!({"url": url, "queueId": 51});
        assert_eq!(ci.parse("queue.view", &queue).unwrap().queue_id, Some(51));
        let permalink = json!({"url":"https://ci.example.com/team-ci/job/payments/job/build-api/lastFailedBuild/"});
        let input = ci.parse("build.log.read", &permalink).unwrap();
        assert_eq!(input.build_selector, Some("lastFailedBuild"));
        assert_eq!(input.build_number, None);
        // Job URL with explicit build input.
        let job_url = "https://ci.example.com/team-ci/job/payments/job/build-api/";
        let with_number = json!({"url": job_url, "buildNumber": 7});
        assert_eq!(
            ci.parse("build.view", &with_number).unwrap().build_number,
            Some(7)
        );
        let with_selector = json!({"url": job_url, "buildSelector": "lastBuild"});
        assert_eq!(
            ci.parse("build.view", &with_selector)
                .unwrap()
                .build_selector,
            Some("lastBuild")
        );
    }

    #[test]
    fn build_and_locator_conflicts_name_the_field() {
        let ci = provider();
        let job_url = "https://ci.example.com/team-ci/job/payments/job/build-api/";
        let build_url = "https://ci.example.com/team-ci/job/payments/job/build-api/42/";
        for (action, inputs, expected) in [
            (
                "build.view",
                json!({"url": job_url}),
                ("build_missing", Some("buildNumber")),
            ),
            (
                "build.view",
                json!({"controller":"team-ci","job":"payments/build-api"}),
                ("build_missing", Some("buildNumber")),
            ),
            (
                "build.view",
                json!({"url": build_url, "buildNumber": 42}),
                ("build_conflict", Some("buildNumber")),
            ),
            (
                "build.view",
                json!({"url": build_url, "buildSelector": "lastBuild"}),
                ("build_conflict", Some("buildSelector")),
            ),
            (
                "build.view",
                json!({"controller":"team-ci","job":"a","buildNumber":1,"buildSelector":"lastBuild"}),
                ("build_conflict", Some("buildSelector")),
            ),
            (
                "job.view",
                json!({"url": job_url, "controller":"team-ci"}),
                ("locator_conflict", Some("url")),
            ),
            (
                "job.view",
                json!({"url": job_url, "job":"payments/build-api"}),
                ("locator_conflict", Some("url")),
            ),
            (
                "job.view",
                json!({}),
                ("locator_missing", Some("controller")),
            ),
            (
                "job.view",
                json!({"job":"payments/build-api"}),
                ("locator_missing", Some("controller")),
            ),
            (
                "job.view",
                json!({"controller":"team-ci"}),
                ("locator_missing", Some("job")),
            ),
            (
                "build.log.read",
                json!({"controller":"team-ci","job":"a","buildSelector":"lastBuild","mode":"head","cursor":"x"}),
                ("option_conflict", Some("cursor")),
            ),
            (
                "build.log.read",
                json!({"url":"https://ci.example.com/team-ci/job/a/lastBuild/","mode":"head","cursor":"x"}),
                ("option_conflict", Some("cursor")),
            ),
        ] {
            let error = ci.parse(action, &inputs).unwrap_err();
            assert_eq!(category(&error), expected, "{inputs}");
        }
        // A numeric build URL may continue a cursor.
        let continued = json!({"url": build_url, "mode":"head", "cursor":"x"});
        assert!(ci.parse("build.log.read", &continued).is_ok());
    }

    #[test]
    fn field_errors_name_the_field_and_likely_mistake() {
        let ci = provider();
        let base = |extra: Value| {
            let mut inputs =
                json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42});
            for (key, value) in extra.as_object().unwrap() {
                if value.is_null() {
                    inputs.as_object_mut().unwrap().remove(key);
                } else {
                    inputs[key] = value.clone();
                }
            }
            inputs
        };
        for (action, inputs, expected, mention) in [
            (
                "build.view",
                base(json!({"jobName":"x"})),
                ("unknown_field", Some("jobName")),
                "accepted inputs: controller, job, url, buildNumber, buildSelector",
            ),
            (
                "job.view",
                json!({"controller":"team-ci","job":"a","buildNumber":1}),
                ("unknown_field", Some("buildNumber")),
                "accepted inputs: controller, job, url",
            ),
            (
                "build.view",
                base(json!({"controller":"team"})),
                ("controller_not_configured", Some("controller")),
                "resources_list",
            ),
            (
                "build.view",
                base(json!({"controller":"ci.example.com"})),
                ("controller_not_alias", Some("controller")),
                "host name",
            ),
            (
                "build.view",
                base(json!({"controller":"https://ci.example.com/team-ci/"})),
                ("controller_not_alias", Some("controller")),
                "not a URL",
            ),
            (
                "build.view",
                base(json!({"controller":"team-ci/payments/build-api"})),
                ("controller_not_alias", Some("controller")),
                "first segment",
            ),
            (
                "build.view",
                base(json!({"controller":7})),
                ("value_invalid", Some("controller")),
                "string",
            ),
            (
                "build.view",
                base(json!({"job":"https://ci.example.com/team-ci/job/payments/"})),
                ("job_is_url", Some("job")),
                "pass the URL as url",
            ),
            (
                "build.view",
                base(json!({"job":"payments/build-api/"})),
                ("job_invalid", Some("job")),
                "trailing",
            ),
            (
                "build.view",
                base(json!({"job":"/payments/build-api"})),
                ("job_invalid", Some("job")),
                "leading",
            ),
            (
                "build.view",
                base(json!({"job":"payments//build-api"})),
                ("job_invalid", Some("job")),
                "repeated",
            ),
            (
                "build.view",
                base(json!({"job":""})),
                ("job_invalid", Some("job")),
                "item names",
            ),
            (
                "build.view",
                base(json!({"job":"payments/Build Api "})),
                ("job_invalid", Some("job")),
                "whitespace",
            ),
            (
                "build.view",
                base(json!({"job":"payments/a?b"})),
                ("job_invalid", Some("job")),
                "character",
            ),
            (
                "build.view",
                base(json!({"job":"payments/../x"})),
                ("job_invalid", Some("job")),
                "..",
            ),
            (
                "build.view",
                base(json!({"buildNumber":"42"})),
                ("value_invalid", Some("buildNumber")),
                "not a string",
            ),
            (
                "build.view",
                base(json!({"buildNumber":"lastBuild"})),
                ("value_invalid", Some("buildNumber")),
                "buildSelector",
            ),
            (
                "build.view",
                base(json!({"buildNumber":0})),
                ("value_invalid", Some("buildNumber")),
                "positive integer",
            ),
            (
                "build.view",
                base(json!({"buildNumber":4_294_967_296_u64})),
                ("value_invalid", Some("buildNumber")),
                "positive integer",
            ),
            (
                "build.view",
                base(json!({"buildNumber":null,"buildSelector":"latest"})),
                ("value_invalid", Some("buildSelector")),
                "lastFailedBuild",
            ),
            (
                "build.view",
                base(json!({"buildNumber":null,"buildSelector":42})),
                ("value_invalid", Some("buildSelector")),
                "buildNumber",
            ),
            (
                "queue.view",
                json!({"controller":"team-ci","job":"a"}),
                ("field_missing", Some("queueId")),
                "build.trigger",
            ),
            (
                "queue.view",
                json!({"controller":"team-ci","job":"a","queueId":0}),
                ("value_invalid", Some("queueId")),
                "positive integer",
            ),
            (
                "build.list",
                json!({"controller":"team-ci","job":"a","maxResults":51}),
                ("value_invalid", Some("maxResults")),
                "1 to 50",
            ),
            (
                "build.pipeline.node.view",
                base(json!({"nodeId":7})),
                ("value_invalid", Some("nodeId")),
                "decimal string",
            ),
            (
                "build.pipeline.node.view",
                base(json!({})),
                ("field_missing", Some("nodeId")),
                "build.pipeline.view",
            ),
            (
                "build.artifact.download",
                base(json!({"artifactPath":"../x"})),
                ("value_invalid", Some("artifactPath")),
                "build.artifact.list",
            ),
            (
                "build.artifact.download",
                base(json!({})),
                ("field_missing", Some("artifactPath")),
                "build.artifact.list",
            ),
            (
                "build.log.read",
                base(json!({"mode":"middle"})),
                ("value_invalid", Some("mode")),
                "head, tail, or search",
            ),
            (
                "build.log.read",
                base(json!({"maxBytes":10})),
                ("value_invalid", Some("maxBytes")),
                "1024 to 65536",
            ),
            (
                "build.log.read",
                base(json!({"mode":"search"})),
                ("value_invalid", Some("query")),
                "query",
            ),
            (
                "build.log.read",
                base(json!({"query":"x"})),
                ("option_conflict", Some("query")),
                "search",
            ),
            (
                "build.log.read",
                base(json!({"cursor":"x"})),
                ("option_conflict", Some("cursor")),
                "tail",
            ),
        ] {
            let error = ci.local_scopes(action, &inputs).unwrap_err();
            assert_eq!(category(&error), expected, "{action} {inputs}");
            assert!(
                error.message.contains(mention),
                "{action} {inputs}: {}",
                error.message
            );
            assert!(!error.message.contains("invalid CloudBees CI action input"));
            for configured in ["nested", "twin-a", "twin-b"] {
                assert!(!error.message.contains(configured), "{}", error.message);
            }
        }
        let long = "x".repeat(65);
        let mut inputs = json!({"controller":"team-ci","job":"a"});
        inputs[long.as_str()] = json!(1);
        let error = ci.parse("job.view", &inputs).unwrap_err();
        assert_eq!(category(&error), ("unknown_field", None));
        assert!(!error.message.contains(&long));
    }

    #[test]
    fn folder_named_job_round_trips_through_discovery_urls_and_locators() {
        let ci = provider();
        let input_value = json!({"url":"https://ci.example.com/team-ci/job/job/job/x/"});
        let input = ci.parse("job.view", &input_value).unwrap();
        assert_eq!(input.job, "job/x");
        // The same full name is accepted explicitly, so URL-derived safe
        // locators and discovery inputs can be passed back unchanged.
        let locator = json!({"controller":input.controller,"job":input.job});
        assert_eq!(ci.parse("job.view", &locator).unwrap().job, "job/x");
        let projected = job_action_inputs(&ResourceSelector::Exact {
            value: "team-ci/job/x".into(),
        })
        .unwrap();
        assert_eq!(Value::Object(projected.clone()), locator);
        let mut build = projected;
        build.insert("buildNumber".into(), json!(1));
        assert!(ci.parse("build.view", &Value::Object(build)).is_ok());
        assert!(has_url_job_segments("job/payments/job/build-api"));
        assert!(!has_url_job_segments("job/payments/build-api"));
    }

    #[test]
    fn locator_schemas_reject_the_mixed_inputs_parsing_rejects() {
        let ci = provider();
        let job_url = "https://ci.example.com/team-ci/job/payments/job/build-api/";
        let build_url = "https://ci.example.com/team-ci/job/payments/job/build-api/42/";
        let cases = [
            (
                "job.view",
                json!({"controller":"team-ci","job":"payments/build-api"}),
                true,
            ),
            ("job.view", json!({"url":job_url}), true),
            (
                "job.view",
                json!({"url":job_url,"controller":"team-ci"}),
                false,
            ),
            (
                "job.view",
                json!({"url":job_url,"job":"payments/build-api"}),
                false,
            ),
            (
                "job.view",
                json!({"url":job_url,"controller":"team-ci","job":"payments/build-api"}),
                false,
            ),
            ("job.view", json!({"controller":"team-ci"}), false),
            ("job.view", json!({}), false),
            (
                "build.view",
                json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42}),
                true,
            ),
            ("build.view", json!({"url":job_url,"buildNumber":42}), true),
            (
                "build.view",
                json!({"url":job_url,"buildSelector":"lastFailedBuild"}),
                true,
            ),
            (
                "build.view",
                json!({"url":job_url,"controller":"team-ci","buildNumber":42}),
                false,
            ),
            (
                "build.view",
                json!({"url":job_url,"job":"payments/build-api","buildNumber":42}),
                false,
            ),
            (
                "build.view",
                json!({"url":build_url,"controller":"team-ci","job":"payments/build-api"}),
                false,
            ),
            (
                "build.view",
                json!({"controller":"team-ci","buildNumber":42}),
                false,
            ),
            (
                "build.view",
                json!({"job":"payments/build-api","buildNumber":42}),
                false,
            ),
            (
                "build.view",
                json!({"controller":"team-ci","job":"payments/build-api"}),
                false,
            ),
            (
                "build.view",
                json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42,
                    "buildSelector":"lastBuild"}),
                false,
            ),
            (
                "build.view",
                json!({"url":job_url,"buildNumber":42,"buildSelector":"lastBuild"}),
                false,
            ),
            ("queue.view", json!({"url":job_url,"queueId":7}), true),
            (
                "queue.view",
                json!({"url":job_url,"controller":"team-ci","queueId":7}),
                false,
            ),
        ];
        for (action, inputs, valid) in cases {
            let validator = jsonschema::validator_for(&schema(action)).unwrap();
            assert_eq!(
                validator.is_valid(&inputs),
                valid,
                "schema {action} {inputs}"
            );
            assert_eq!(
                ci.parse(action, &inputs).is_ok(),
                valid,
                "parse {action} {inputs}"
            );
        }
    }

    #[test]
    fn action_inputs_project_exact_and_namespace_selectors() {
        let project = |selector| CLOUDBEES_CI_JOB_RESOURCE.action_inputs(&selector);
        assert_eq!(
            project(ResourceSelector::Exact {
                value: "team-ci/payments/build-api".into()
            }),
            json!({"controller":"team-ci","job":"payments/build-api"})
                .as_object()
                .cloned()
        );
        for namespace in ["team-ci", "team-ci/payments"] {
            assert_eq!(
                project(ResourceSelector::Namespace {
                    value: namespace.into()
                }),
                json!({"controller":"team-ci"}).as_object().cloned()
            );
        }
        assert_eq!(project(ResourceSelector::All), None);
    }

    #[test]
    fn resource_roots_are_configured_aliases_for_jobs_only() {
        let ci = provider();
        assert_eq!(
            ci.resource_roots(CLOUDBEES_CI_JOB_RESOURCE.id()),
            ["nested", "root", "team-ci", "twin-a", "twin-b"]
        );
        assert!(
            ci.resource_roots(&ResourceType::from_static("git_repository"))
                .is_empty()
        );
    }

    #[test]
    fn schemas_express_locator_and_build_alternatives() {
        let validator = |action| jsonschema::validator_for(&schema(action)).unwrap();
        let build = validator("build.view");
        for valid in [
            json!({"controller":"team-ci","job":"a","buildNumber":1}),
            json!({"controller":"team-ci","job":"a","buildSelector":"lastFailedBuild"}),
            json!({"url":"https://ci.example.com/team-ci/job/a/1/"}),
            json!({"url":"https://ci.example.com/team-ci/job/a/","buildNumber":1}),
        ] {
            assert!(build.is_valid(&valid), "{valid}");
        }
        for invalid in [
            json!({"controller":"team-ci","job":"a"}),
            json!({"controller":"team-ci","job":"a","buildNumber":1,"buildSelector":"lastBuild"}),
            json!({"url":"u","controller":"team-ci","job":"a","buildNumber":1}),
            json!({"controller":"team-ci","job":"a","buildSelector":"latest"}),
        ] {
            assert!(!build.is_valid(&invalid), "{invalid}");
        }
        let job = validator("job.view");
        assert!(job.is_valid(&json!({"url":"u"})));
        assert!(!job.is_valid(&json!({"url":"u","buildNumber":1})));
        assert!(!job.is_valid(&json!({"url":"u","controller":"c","job":"j"})));
        let log = validator("build.log.read");
        assert!(
            !log.is_valid(
                &json!({"url":"u","buildSelector":"lastBuild","mode":"head","cursor":"c"})
            )
        );
        let queue = validator("queue.view");
        assert!(!queue.is_valid(&json!({"url":"u"})));
        assert!(queue.is_valid(&json!({"url":"u","queueId":1})));
        let properties = &schema("build.view")["properties"];
        for field in ["controller", "job", "url", "buildNumber", "buildSelector"] {
            assert!(properties[field]["description"].is_string(), "{field}");
        }
    }
}
