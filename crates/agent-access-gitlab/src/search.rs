//! Bounded, result-filtered repository discovery and native content search.
//! Candidate metadata never enters provider results, audit, or continuations.
use super::*;
use reqwest::header::HeaderMap;
use std::sync::atomic::{AtomicBool, Ordering};

mod pagination;
mod projection;
#[cfg(test)]
mod tests;

pub(crate) const CATEGORIES: &[&str] = &[
    "issues",
    "merge_requests",
    "code",
    "commits",
    "wiki",
    "comments",
];
const SEARCH_TOKENS: ContinuationFamily = ContinuationFamily::new(
    "gitlab",
    "native-search",
    1,
    ContinuationLifetime::StableWhenConfigured,
    32,
)
.confidential()
.fixed_payload_length()
.expires_after(Duration::from_secs(900))
.clock_skew(Duration::from_secs(60));

pub(crate) fn is_search_action(action: &str) -> bool {
    is_project_collection(action)
        || action
            .strip_prefix("search.")
            .is_some_and(|v| CATEGORIES.contains(&v))
}

fn is_project_collection(action: &str) -> bool {
    matches!(action, "project.list" | "project.search")
}

fn invalid() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "GitLab search inputs are invalid or unsupported",
    )
}
fn invalid_input(message: &'static str) -> ProviderError {
    ProviderError::deny(ReasonCode::InputInvalid, message)
}
fn invalid_project_route(action: &str, engine: &str, has_project: bool) -> ProviderError {
    // Only publish fixed catalog names, never supplied strings or hidden config.
    let action: &'static str = match action {
        "search.issues" => "search.issues",
        "search.merge_requests" => "search.merge_requests",
        "search.code" => "search.code",
        "search.commits" => "search.commits",
        "search.wiki" => "search.wiki",
        "search.comments" => "search.comments",
        _ => return invalid_input("GitLab search engine is not enabled for this action"),
    };
    let engine: &'static str = match engine {
        "basic" => "basic",
        "advanced" => "advanced",
        "zoekt" => "zoekt",
        _ => return invalid_input("GitLab search engine is not enabled for this action"),
    };
    ProviderError::deny(
        ReasonCode::InputInvalid,
        if has_project {
            format!("GitLab {action} does not accept project with engine {engine}; omit project")
        } else {
            format!("GitLab {action} requires project with engine {engine}")
        },
    )
}
fn protocol() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "GitLab search response protocol error",
    )
}
fn bounded_work() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "GitLab search work budget was exceeded",
    )
}

#[derive(Serialize)]
struct SearchInputs {
    search: Option<String>,
    project: Option<String>,
    engine: Option<String>,
    regex: Option<bool>,
    include_namespaces: bool,
    archived: Option<bool>,
    max_results: u32,
    #[serde(skip)]
    page_token: Option<String>,
}

fn parse_inputs(
    action: &str,
    value: &Value,
    config: &GitlabSearchConfig,
) -> Result<SearchInputs, ProviderError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_input("GitLab search inputs must be an object"))?;
    let discovery = is_project_collection(action);
    let allowed: &[&str] = if action == "project.list" {
        &["maxResults", "pageToken"]
    } else if discovery {
        &[
            "search",
            "includeNamespaces",
            "archived",
            "maxResults",
            "pageToken",
        ]
    } else if action == "search.code" {
        &[
            "search",
            "project",
            "engine",
            "regex",
            "maxResults",
            "pageToken",
        ]
    } else {
        &["search", "project", "engine", "maxResults", "pageToken"]
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid_input(match action {
            "project.list" => "GitLab project.list accepts only maxResults and pageToken",
            "project.search" => {
                "GitLab project.search accepts only search, includeNamespaces, archived, maxResults and pageToken"
            }
            "search.code" => {
                "GitLab search.code accepts only search, project, engine, regex, maxResults and pageToken"
            }
            _ => {
                "GitLab content search accepts only search, project, engine, maxResults and pageToken"
            }
        }));
    }
    let string = |key: &str, message: &'static str| -> Result<Option<String>, ProviderError> {
        object
            .get(key)
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| invalid_input(message))
            })
            .transpose()
    };
    let boolean = |key: &str, message: &'static str| -> Result<Option<bool>, ProviderError> {
        object
            .get(key)
            .map(|v| v.as_bool().ok_or_else(|| invalid_input(message)))
            .transpose()
    };
    let search = string("search", "GitLab search requires search to be a string")?
        .map(|v| v.trim().to_string());
    if search
        .as_ref()
        .is_some_and(|v| v.is_empty() || v.len() > 512)
        || (!discovery && search.is_none())
    {
        return Err(invalid_input(
            "GitLab search requires search to contain 1–512 UTF-8 bytes after trimming; omit it only for project discovery",
        ));
    }
    let project = string("project", "GitLab search project must be a string")?;
    if project
        .as_ref()
        .is_some_and(|v| !is_canonical_repository_path(v))
    {
        return Err(invalid_input(
            "GitLab search project must be a canonical namespace/project path",
        ));
    }
    let engine = if discovery {
        None
    } else {
        Some(
            string("engine", "GitLab search engine must be a string")?
                .unwrap_or_else(|| config.default_engine.clone()),
        )
    };
    if let Some(engine) = engine.as_deref() {
        let category = action.strip_prefix("search.").ok_or_else(invalid)?;
        if !config.supports(engine, category, project.is_some()) {
            return Err(if config.supports(engine, category, project.is_none()) {
                invalid_project_route(action, engine, project.is_some())
            } else {
                invalid_input("GitLab search engine is not enabled for this action")
            });
        }
    }
    let regex = boolean("regex", "GitLab search regex must be a boolean")?;
    if regex.is_some() && (action != "search.code" || engine.as_deref() != Some("zoekt")) {
        return Err(invalid_input(
            "GitLab search regex is accepted only with engine zoekt, including regex: false",
        ));
    }
    let regex = (engine.as_deref() == Some("zoekt")).then_some(regex.unwrap_or(false));
    let max_results = match object.get("maxResults") {
        Some(v) => v
            .as_u64()
            .filter(|v| *v > 0 && *v <= u64::from(config.max_results.min(100)))
            .ok_or_else(|| {
                invalid_input(
                    "GitLab search maxResults must be an integer within the published range",
                )
            })? as u32,
        None => config.max_results.min(100),
    };
    if max_results == 0 {
        return Err(invalid_input(
            "GitLab search maxResults must be an integer within the published range",
        ));
    }
    let page_token = string("pageToken", "GitLab search pageToken must be a string")?;
    if page_token
        .as_ref()
        .is_some_and(|v| v.is_empty() || v.len() > 512 || !v.is_ascii())
    {
        return Err(invalid_input(
            "GitLab search pageToken must contain 1–512 ASCII bytes",
        ));
    }
    Ok(SearchInputs {
        search,
        project,
        engine,
        regex,
        include_namespaces: boolean(
            "includeNamespaces",
            "GitLab search includeNamespaces must be a boolean",
        )?
        .unwrap_or(true),
        archived: boolean("archived", "GitLab search archived must be a boolean")?,
        max_results,
        page_token,
    })
}

pub(crate) fn descriptors(config: &GitlabProviderConfig) -> Vec<ActionDescriptor> {
    let common = |action: &str, description: &str, schema: Value, documentation: Value| {
        ActionDescriptor::new(action, description, schema)
            .scope("repository")
            .credential_modes(["service", "per_user"])
            .native_search(NativeSearchEnforcement::ResultFiltered)
            .read_only()
            .sensitive_output("/result/items")
            .sensitive_output("/result/nextPageToken")
            .documentation(documentation)
    };
    let search = &config.search;
    let base = || {
        json!({
            "type":"object", "additionalProperties":false,
            "properties":{
                "search":{"type":"string","minLength":1,"maxLength":512},
                "maxResults":{"type":"integer","minimum":1,"maximum":search.max_results},
                "pageToken":{"type":"string","minLength":1,"maxLength":512}
            }
        })
    };
    let pagination = json!({
        "maxResults":search.max_results, "requestTokenField":"pageToken", "responseTokenField":"nextPageToken",
        "tokenLifetimeMinutes":15,
        "continuation":"Keep all inputs unchanged. Confidential tokens carry the original expiry and are reauthorized on every request. Short pages do not prove completion. more and scan_budget mean upstream work remains, not that another authorized match exists. exhausted ends this observed stream; upstream_window is incomplete coverage. Empty resumable pages may occur repeatedly when GitLab can see many repositories outside the Broker boundary."
    });
    let mut discovery = base();
    discovery["properties"]["includeNamespaces"] = json!({"type":"boolean","default":true});
    discovery["properties"]["archived"] = json!({"type":"boolean"});
    let mut actions = vec![common(
        "project.search",
        "Discover or browse authorized GitLab projects live, including projects covered by namespace grants that are absent from resource_access_describe registeredResources.items",
        discovery,
        json!({"query":"Omit search to browse. A supplied query must contain 1–512 UTF-8 bytes after trimming; GitLab matches name, path, description and optionally ancestor namespaces. * has no special Broker meaning. Current upstream projects, including new namespace descendants, supply the inventory.","ordering":"Ascending project ID with keyset pagination; no snapshot isolation.","pagination":pagination,"previews":"Descriptions are capped at 4096 UTF-8 bytes with previewTruncated. Locators are optional and checked against current identity."}),
    )
    .audit_input("search", "Search")];
    let mut listing = base();
    listing["properties"]
        .as_object_mut()
        .unwrap()
        .remove("search");
    actions.push(common(
        "project.list",
        "List live GitLab projects within effective repository grants",
        listing,
        json!({
            "listing":"Lists visible archived and unarchived projects without a query. Namespace/all grants can include projects absent from the local resource catalog. Every candidate is filtered through this action's effective grants, exclusions and token restrictions; project.search permissions do not grant project.list.",
            "ordering":"Ascending project ID with keyset pagination; no snapshot isolation.",
            "pagination":pagination,
            "limits":"Shares the configured GitLab search result, candidate-page, HTTP-attempt and byte limits.",
            "previews":"Descriptions are capped at 4096 UTF-8 bytes with previewTruncated. Locators are optional and checked against current identity."
        }),
    ).listing_of(GIT_REPOSITORY_RESOURCE.id().clone()));
    for category in CATEGORIES {
        let engines = search.enabled_engines(category);
        if engines.is_empty() {
            continue;
        }
        let action = format!("search.{category}");
        let mut schema = base();
        let project_only = engines
            .iter()
            .all(|engine| !search.supports(engine, category, false));
        let instance_only = engines
            .iter()
            .all(|engine| !search.supports(engine, category, true));
        let both_routes = engines.iter().all(|engine| {
            search.supports(engine, category, true) && search.supports(engine, category, false)
        });
        let route_guidance = if project_only {
            "project is required with every configured engine.".to_string()
        } else if instance_only {
            "Omit project with every configured engine.".to_string()
        } else if both_routes {
            "Omit project to search across authorized repositories, or give project to search one."
                .to_string()
        } else {
            engines
                .iter()
                .map(|engine| {
                    if !search.supports(engine, category, false) {
                        format!("project is required when engine is {engine}.")
                    } else if !search.supports(engine, category, true) {
                        format!("Omit project when engine is {engine}.")
                    } else {
                        format!("project is optional when engine is {engine}.")
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        };
        let default_guidance = format!("Omit engine to use {}.", search.default_engine);
        let project_guidance = if project_only {
            "Required with every configured engine."
        } else if instance_only {
            "Not available with the configured search engines; omit."
        } else if both_routes {
            "Omit to search across authorized repositories, or give project to search one."
        } else {
            &route_guidance
        };
        schema["required"] = if project_only {
            json!(["search", "project"])
        } else {
            json!(["search"])
        };
        schema["properties"]["project"] = json!({
            "type":"string","minLength":3,
            "description":format!("Canonical namespace/project path. {project_guidance} {default_guidance}")
        });
        let regex_available = *category == "code" && engines.contains(&"zoekt");
        let regex_guidance = if regex_available {
            " regex is accepted only with engine zoekt, including regex: false."
        } else {
            ""
        };
        schema["properties"]["engine"] = json!({
            "type":"string","enum":engines,"default":search.default_engine,
            "description":format!("Search engine. {default_guidance} {route_guidance}{regex_guidance}")
        });
        if regex_available {
            schema["properties"]["regex"] = json!({
                "type":"boolean","default":false,
                "description":format!("Use native code regular expressions. Only with engine zoekt, including regex: false. Omitted defaults to false with zoekt. {default_guidance}")
            });
        }
        let routes: Value = engines.iter().map(|engine| ((*engine).to_string(), json!({"project":search.supports(engine,category,true),"instance":search.supports(engine,category,false)}))).collect();
        let mut documentation = json!({"engines":routes,"defaultEngine":search.default_engine,
                "engine":"Omit engine to use the service's configured default.",
                "availability":"Engine and route support is operator configured, not a live health or index-completeness check. project is required when the effective engine has no instance route. No alternate engine or per-project crawling fallback is used.",
                "query":"Required native engine expression: 1–512 UTF-8 bytes after trimming. Native operators, tokenization and ranking vary by engine; there is no JQL/CQL or Broker rewrite. Code regex is accepted only with zoekt and is sent explicitly.",
                "nativeSyntax":{
                    "basic":"GitLab basic text matching. Code/wiki queries support native filename:, path:, and extension: filters, for example needle path:src/*. No Broker operator parsing or rewriting occurs.",
                    "advanced":"GitLab advanced full-text syntax and indexed matching; native phrases, exclusions and category filters follow the deployment's advanced-search grammar.",
                    "zoekt":"Exact code search uses Zoekt grammar. regex=false is sent by default; regex=true requests native regular expressions. Elasticsearch wildcard expressions are not translated to Zoekt expressions.",
                    "references":["https://docs.gitlab.com/user/search/","https://docs.gitlab.com/user/search/advanced_search/","https://docs.gitlab.com/user/search/exact_code_search/"]
                },
                "coverage":"Search uses the selected engine's default branch/index coverage and upstream archived/fork defaults; it does not search every branch or historical file. Advanced search has a 10,000-candidate retrieval window. Deployment qualification must record enabled scope, branch, archived and fork coverage. Offset pagination and changing indexes can repeat or omit results.",
                "ownership":"Repository authorization uses current confirmed project paths with the admitted execution credential. Descriptions and snippets are untrusted upstream text. No ordinary object-read action is implied.",
                "previews":"Previews and upstream snippets are capped at 4096 UTF-8 bytes on character boundaries with previewTruncated. Snippets identify upstream excerpts, not a guarantee of the exact match. Locators are optional.","pagination":pagination});
        if *category == "wiki" {
            documentation["reading"] = json!(
                "Returns bounded snippets supplied by GitLab, not full wiki pages. A snippet may omit the matching passage. A returned GitLab URL can be used to locate the page. Full wiki-page reading is not currently supported by the Broker; file.view reads source-repository files and cannot read wiki pages."
            );
        }
        let action_routes = if project_only {
            "in one project".to_string()
        } else if instance_only {
            "across authorized repositories".to_string()
        } else if both_routes {
            "across authorized repositories; give project to search one".to_string()
        } else {
            format!(
                "across authorized repositories or one project. {route_guidance} {default_guidance}"
            )
        };
        let descriptor = common(
            &action,
            &format!("Native full-text search of GitLab {category} {action_routes}"),
            schema,
            documentation,
        )
        .audit_input("project", "Project")
        .audit_input("search", "Search");
        // Zoekt's regex flag changes how the recorded search is read.
        actions.push(if regex_available {
            descriptor.audit_input("regex", "Regex")
        } else {
            descriptor
        });
    }
    actions
}

pub(crate) struct HttpSearchBackend {
    api_base: Url,
    client: UpstreamClient,
    response_cap: u64,
}

struct Operation {
    requests: UpstreamRequestBudget,
    bytes: SharedBodyBudget,
    replay_used: AtomicBool,
}
impl Operation {
    fn new(config: &GitlabSearchConfig) -> Self {
        Self {
            requests: UpstreamRequestBudget::new(config.max_upstream_requests),
            bytes: SharedBodyBudget::new(config.max_scan_bytes),
            replay_used: AtomicBool::new(false),
        }
    }
    fn retry_allowance(&self) -> u32 {
        u32::from(!self.replay_used.load(Ordering::Acquire))
    }
}
enum ProjectLookup<'a> {
    Explicit(&'a str),
    Candidate(u64),
}

struct SearchResponse {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}
impl SearchResponse {
    fn json(&self) -> Result<Value, ProviderError> {
        serde_json::from_slice(&self.body).map_err(|_| protocol())
    }
    fn successful(&self) -> Result<(), ProviderError> {
        let error = match self.status {
            200..=299 => return Ok(()),
            401 => GitlabBackendError::Unauthorized,
            403 => GitlabBackendError::Forbidden,
            404 => GitlabBackendError::NotFound,
            429 => GitlabBackendError::RateLimited(UpstreamRetryAfter::from_headers(&self.headers)),
            _ => GitlabBackendError::HttpStatus(self.status),
        };
        Err(gitlab_backend_error(error))
    }
}

impl HttpSearchBackend {
    pub(crate) fn new(
        config: &GitlabProviderConfig,
        limits: &ProviderLimits,
        clients: &dyn agent_access_provider::host::UpstreamClientFactory,
    ) -> Result<Self, ProviderBuildError> {
        let api_base = normalized_api_base(&config.api_base_url)
            .map_err(|_| ProviderBuildError::invalid("GitLab search API base is invalid"))?;
        let client = UpstreamClient::build(
            UpstreamClientSpec::new(
                "providers.gitlab.egress_proxy",
                "gitlab",
                &api_base,
                EgressDeclaration::Ordinary(config.egress_proxy.as_ref()),
                &config.allowed_upstream_hosts,
                ClientProfile::SingleAttempt,
            ),
            clients,
        )?;
        Ok(Self {
            api_base,
            client,
            response_cap: limits.max_upstream_response_bytes,
        })
    }
    fn endpoint(&self, path: &str) -> Result<Url, ProviderError> {
        self.api_base.join(path).map_err(|_| protocol())
    }
    async fn get(
        &self,
        url: &Url,
        action: &str,
        credential: &GitlabCredential,
        op: &Operation,
    ) -> Result<SearchResponse, ProviderError> {
        let mut attempt = 1;
        loop {
            let presented = credential.present().await.map_err(gitlab_backend_error)?;
            let mut response = self
                .client
                .send(
                    self.client
                        .request(Method::GET, url.clone())
                        .header("Accept", "application/json"),
                    UpstreamCall::new(action)
                        .with_attempt(attempt)
                        .with_authorization(&presented.authorization)
                        .with_request_budget(&op.requests),
                )
                .await
                .map_err(|error| {
                    if matches!(error, UpstreamError::RequestBudgetExceeded) {
                        bounded_work()
                    } else {
                        gitlab_backend_error(gitlab_upstream_error(error))
                    }
                })?;
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            complete_upstream_trace(&mut response, None);
            if status == 401 && presented.is_delegated() {
                credential
                    .mark_rejected(&presented)
                    .map_err(gitlab_backend_error)?;
            }
            let body =
                read_bounded_body_with_budget(response, self.response_cap, None, Some(&op.bytes))
                    .await
                    .map_err(|error| match error {
                        BodyReadError::BudgetExceeded => bounded_work(),
                        BodyReadError::TooLarge => {
                            gitlab_backend_error(GitlabBackendError::ResponseTooLarge)
                        }
                        BodyReadError::IdleTimeout
                        | BodyReadError::Transport {
                            timed_out: true, ..
                        } => gitlab_backend_error(GitlabBackendError::Timeout),
                        BodyReadError::Transport {
                            timed_out: false, ..
                        } => gitlab_backend_error(GitlabBackendError::Transport(String::new())),
                        _ => protocol(),
                    })?;
            if status == 401 && presented.is_delegated() {
                let replay = op
                    .replay_used
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
                credential
                    .recover_rejected(replay.then_some(()))
                    .await
                    .map_err(gitlab_backend_error)?;
                attempt += 1;
                continue;
            }
            return Ok(SearchResponse {
                status,
                headers,
                body,
            });
        }
    }
    async fn project(
        &self,
        lookup: ProjectLookup<'_>,
        action: &str,
        credential: &GitlabCredential,
        op: &Operation,
    ) -> Result<Option<projection::Project>, ProviderError> {
        let (locator, expected, candidate) = match lookup {
            ProjectLookup::Explicit(path) => (path.to_string(), None, false),
            ProjectLookup::Candidate(id) => (id.to_string(), Some(id), true),
        };
        let url = self.endpoint(&format!("projects/{}", encoded_path_segment(&locator)))?;
        let mut response = self.get(&url, action, credential, op).await?;
        let mut moved_to = None;
        if !candidate && response.status == 301 {
            let id =
                backend::moved_project_id(&url, &response.headers).map_err(gitlab_backend_error)?;
            response = self
                .get(
                    &self.endpoint(&format!("projects/{id}"))?,
                    action,
                    credential,
                    op,
                )
                .await?;
            moved_to = Some(id);
        }
        if candidate && matches!(response.status, 403 | 404) {
            return Ok(None);
        }
        response.successful()?;
        let project = projection::Project::parse(&response.json()?)?;
        if expected.or(moved_to).is_some_and(|id| id != project.id) {
            return Err(protocol());
        }
        Ok(Some(project))
    }
    fn collection_url(
        &self,
        action: &str,
        input: &SearchInputs,
        project: Option<&projection::Project>,
        position: u64,
    ) -> Result<Url, ProviderError> {
        let mut url = if is_project_collection(action) {
            self.endpoint("projects")?
        } else if let Some(project) = project {
            self.endpoint(&format!("projects/{}/search", project.id))?
        } else {
            self.endpoint("search")?
        };
        let mut query = url.query_pairs_mut();
        query.append_pair("per_page", &input.max_results.to_string());
        if is_project_collection(action) {
            query
                .append_pair("simple", "false")
                .append_pair("pagination", "keyset")
                .append_pair("order_by", "id")
                .append_pair("sort", "asc")
                .append_pair(
                    "search_namespaces",
                    if input.include_namespaces {
                        "true"
                    } else {
                        "false"
                    },
                );
            if position > 0 {
                query.append_pair("id_after", &position.to_string());
            }
            if let Some(archived) = input.archived {
                query.append_pair("archived", if archived { "true" } else { "false" });
            }
        } else {
            let scope = match action {
                "search.issues" => "issues",
                "search.merge_requests" => "merge_requests",
                "search.code" => "blobs",
                "search.commits" => "commits",
                "search.wiki" => "wiki_blobs",
                "search.comments" => "notes",
                _ => return Err(invalid()),
            };
            query
                .append_pair("scope", scope)
                .append_pair("search_type", input.engine.as_deref().ok_or_else(invalid)?)
                .append_pair("page", &position.to_string());
            if let Some(regex) = input.regex {
                query.append_pair("regex", if regex { "true" } else { "false" });
            }
        }
        if let Some(search) = input.search.as_deref() {
            query.append_pair("search", search);
        }
        drop(query);
        Ok(url)
    }
}

impl GitlabProvider {
    pub(crate) async fn invoke_native_search(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let started = Instant::now();
        let action = request.action();
        let input = parse_inputs(action, request.inputs(), &self.config.search)?;
        let authority = request.search_authorization()?;
        if authority.scope_type != "repository" || authority.scope.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "GitLab search has no repository authority",
            ));
        }
        let credential = self.execution_credential(&request)?;
        let backend = self.search_backend.as_ref().ok_or_else(protocol)?;
        let profile = sha256_serialized(
            &json!({"api":self.config.api_base_url,"web":self.config.web_base_url,"search":self.config.search}),
        );
        let base_binding = bind_gitlab_access(
            SEARCH_TOKENS.bind(request.context(), &profile),
            request.execution(),
        )?;
        // The SDK fixes the first expiry before project resolution or any
        // other upstream work. Opening below still requires the complete binding.
        let first_deadline = self
            .pagination_signer
            .deadline(&base_binding)
            .map_err(gitlab_page_token_failure)?;
        let op = Operation::new(&self.config.search);
        let project = if let Some(path) = input.project.as_deref() {
            let confirmed = backend
                .project(ProjectLookup::Explicit(path), action, &credential, &op)
                .await?
                .ok_or_else(protocol)?;
            if !authority.scope.matches(&confirmed.path) {
                return Err(ProviderError::deny(
                    ReasonCode::ServiceActionDenied,
                    "GitLab project is outside the admitted repository boundary",
                ));
            }
            Some(confirmed)
        } else {
            None
        };
        let route: u8 = if is_project_collection(action) {
            1
        } else if project.is_some() {
            3
        } else {
            2
        };
        let binding = base_binding
            .text("inputs", &sha256_serialized(&input))
            .text("boundary", &sha256_serialized(&authority.scope))
            .text(
                "project",
                project.as_ref().map(|v| v.path.as_str()).unwrap_or(""),
            )
            .number("projectId", project.as_ref().map(|v| v.id).unwrap_or(0));
        let opened = input
            .page_token
            .as_ref()
            .map(|token| {
                self.pagination_signer
                    .open_confidential(&binding, token)
                    .map_err(gitlab_page_token_failure)
            })
            .transpose()?;
        let deadline = if let Some(opened) = &opened {
            opened.expiry()
        } else {
            first_deadline
        };
        let mut position = if let Some(opened) = &opened {
            decode_position(opened.payload(), route)?
        } else if route == 1 {
            0
        } else {
            1
        };
        if input.engine.as_deref() == Some("advanced")
            && position
                .checked_mul(u64::from(input.max_results))
                .is_none_or(|n| n > 10_000)
        {
            return Err(gitlab_page_token_error());
        }
        let mut projects = BTreeMap::new();
        let mut paths = BTreeMap::new();
        let mut pages = 0;
        let (items, next, status) = loop {
            let reservation =
                1 + if route == 2 { input.max_results } else { 0 } + op.retry_allowance();
            if pages >= self.config.search.max_candidate_pages
                || op.requests.remaining_requests() < reservation
            {
                if pages == 0 {
                    return Err(bounded_work());
                }
                break (Vec::new(), Some(position), "scan_budget");
            }
            let url = backend.collection_url(action, &input, project.as_ref(), position)?;
            let response = backend.get(&url, action, &credential, &op).await?;
            response.successful()?;
            if let Some(engine) = input.engine.as_deref()
                && pagination::single_header(&response.headers, "x-search-type")? != Some(engine)
            {
                return Err(protocol());
            }
            let body = response.json()?;
            let candidates = body.as_array().ok_or_else(protocol)?;
            if candidates.len() > input.max_results as usize {
                return Err(protocol());
            }
            let next = if route == 1 {
                pagination::keyset(&response.headers, &url, position, candidates)?
            } else {
                pagination::offset(
                    &response.headers,
                    &url,
                    position,
                    input.max_results,
                    candidates.len(),
                    input.engine.as_deref() == Some("advanced"),
                )?
            };
            let mut items = Vec::new();
            for candidate in candidates {
                if route == 1 {
                    let current = projection::Project::parse(candidate)?;
                    check_unique_project_path(&mut paths, &current)?;
                    if !authority.scope.matches(&current.path) {
                        continue;
                    }
                    if input
                        .archived
                        .is_some_and(|archived| current.archived != Some(archived))
                    {
                        continue;
                    }
                    items.push(projection::project_item(candidate, &current, &self.config)?);
                    continue;
                }
                let Some(id) = projection::owner(action, candidate)? else {
                    if project.is_some() {
                        return Err(protocol());
                    }
                    continue;
                };
                let current = if let Some(project) = project.as_ref() {
                    if id != project.id {
                        return Err(protocol());
                    }
                    Some(project)
                } else {
                    if let std::collections::btree_map::Entry::Vacant(entry) = projects.entry(id) {
                        entry.insert(
                            backend
                                .project(ProjectLookup::Candidate(id), action, &credential, &op)
                                .await?,
                        );
                    }
                    projects.get(&id).and_then(Option::as_ref)
                };
                let Some(current) = current else {
                    continue;
                };
                check_unique_project_path(&mut paths, current)?;
                if !authority.scope.matches(&current.path) {
                    continue;
                }
                items.push(projection::content_item(
                    action,
                    candidate,
                    current,
                    &self.config,
                )?);
            }
            pages += 1;
            match next {
                pagination::Next::End => break (items, None, "exhausted"),
                pagination::Next::Window => break (items, None, "upstream_window"),
                pagination::Next::Position(next) if !items.is_empty() => {
                    break (items, Some(next), "more");
                }
                pagination::Next::Position(next) => position = next,
            }
        };
        let token = next
            .map(|position| {
                let payload = encode_position(route, position);
                if let Some(opened) = &opened {
                    self.pagination_signer
                        .seal_resumed(&binding, &payload, opened)
                } else {
                    self.pagination_signer
                        .seal_until(&binding, &payload, deadline)
                }
                .map_err(gitlab_page_token_failure)
            })
            .transpose()?;
        let released_projects: BTreeSet<&str> = items
            .iter()
            .filter_map(|item| item.get("project").and_then(Value::as_str))
            .collect();
        let audit = json!({"gitlab":{"operation":action,"configuredEngine":self.config.search.default_engine,"requestedEngine":request.inputs().get("engine"),"effectiveEngine":input.engine,"routeClass":match route {1=>"projects",2=>"instance",_=>"project"},"returnedCount":items.len(),"scanStatus":status,"continuationPresent":token.is_some(),"projects":released_projects}});
        let mut result = json!({"items":items,"count":items.len(),"maxResults":input.max_results,"scanStatus":status});
        if let Some(engine) = input.engine {
            result["engine"] = json!(engine);
        }
        if let Some(token) = token {
            result["nextPageToken"] = json!(token);
        }
        Ok(ProviderResult::new(result)
            .with_audit(audit)
            .with_upstream(Some(200), Some(elapsed_ms(started))))
    }
}

fn encode_position(route: u8, position: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[0] = route;
    bytes[1..9].copy_from_slice(&position.to_be_bytes());
    bytes
}
fn decode_position(bytes: &[u8], route: u8) -> Result<u64, ProviderError> {
    if bytes.len() != 32 || bytes[0] != route || bytes[9..].iter().any(|v| *v != 0) {
        return Err(gitlab_page_token_error());
    }
    let position = u64::from_be_bytes(
        bytes[1..9]
            .try_into()
            .map_err(|_| gitlab_page_token_error())?,
    );
    if position == 0 {
        return Err(gitlab_page_token_error());
    }
    Ok(position)
}

fn check_unique_project_path(
    paths: &mut BTreeMap<String, u64>,
    project: &projection::Project,
) -> Result<(), ProviderError> {
    if paths
        .insert(project.path.clone(), project.id)
        .is_some_and(|previous| previous != project.id)
    {
        return Err(protocol());
    }
    Ok(())
}
