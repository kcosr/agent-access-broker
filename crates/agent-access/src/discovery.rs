//! Shared caller discovery for CLI and MCP. All resource policy is evaluated by the broker.
use agent_access_core::{ActionList, ApiCatalog, ResourceAccessDescription};
use agent_access_provider::ActionCapabilities;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

#[derive(Debug)]
pub(crate) struct BrokerFailure {
    pub status: u16,
    pub body: Value,
}

#[derive(Debug)]
pub(crate) struct InputError(pub String);

impl std::fmt::Display for BrokerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "broker discovery rejected (HTTP {})", self.status)
    }
}
impl std::error::Error for BrokerFailure {}
impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for InputError {}

fn input(result: Result<()>) -> Result<()> {
    result.map_err(|error| InputError(error.to_string()).into())
}

fn nonempty(name: &str, value: Option<&str>) -> Result<()> {
    if value == Some("") {
        return Err(InputError(format!("{name} must not be empty")).into());
    }
    Ok(())
}

async fn get(
    settings: &crate::ResolvedCliSettings,
    path: &str,
    query: &[(&str, String)],
    shape: crate::ResponseShape,
) -> Result<Value> {
    let client = crate::mcp::tools::mcp_http_client(settings, false)?;
    let response = crate::request_builder(
        client
            .get(crate::endpoint(&settings.url, path)?)
            .query(query),
        settings,
    )
    .send()
    .await
    .map_err(|_| anyhow::anyhow!("broker discovery request failed"))?;
    let (status, value) = crate::mcp::tools::decode_json(response, shape).await?;
    if status >= 400 {
        return Err(BrokerFailure {
            status,
            body: value,
        }
        .into());
    }
    Ok(value)
}

pub(crate) async fn services_list(
    settings: &crate::ResolvedCliSettings,
    prefix: Option<&str>,
    verbose: bool,
) -> Result<Value> {
    input(crate::validate_discovery_prefix(prefix))?;
    let value = get(settings, "/v1/services", &[], crate::ResponseShape::Array).await?;
    crate::project_service_list(
        value,
        &crate::DiscoveryListArgs {
            prefix: prefix.map(str::to_owned),
            verbose,
        },
    )
}

pub(crate) async fn service_describe(
    settings: &crate::ResolvedCliSettings,
    service: &str,
) -> Result<Value> {
    input(crate::validate_service_argument(service))?;
    let value = get(
        settings,
        &format!("/v1/services/{service}"),
        &[],
        crate::ResponseShape::Object,
    )
    .await?;
    let parsed = crate::parse_discovery_service(value)?;
    if parsed.capabilities.service != service {
        bail!("broker returned a different service");
    }
    Ok(parsed.raw)
}

pub(crate) async fn resource_access_describe(
    settings: &crate::ResolvedCliSettings,
    service: &str,
    action: Option<&str>,
    resource_type: Option<&str>,
    prefix: Option<&str>,
    limit: Option<u32>,
    cursor: Option<&str>,
) -> Result<Value> {
    input(crate::validate_service_argument(service))?;
    input(crate::validate_discovery_prefix(prefix))?;
    nonempty("action", action)?;
    nonempty("cursor", cursor)?;
    nonempty("resource type", resource_type)?;
    if limit.is_some_and(|limit| !(1..=100).contains(&limit)) {
        return Err(InputError("limit must be between 1 and 100".into()).into());
    }
    let mut query = Vec::new();
    if let Some(action) = action {
        query.push(("action", action.to_owned()));
    }
    if let Some(resource_type) = resource_type {
        query.push(("resourceType", resource_type.to_owned()));
    }
    if let Some(prefix) = prefix {
        query.push(("prefix", prefix.to_owned()));
    }
    if let Some(limit) = limit {
        query.push(("limit", limit.to_string()));
    }
    if let Some(cursor) = cursor {
        query.push(("cursor", cursor.to_owned()));
    }
    let value = get(
        settings,
        &format!("/v1/services/{service}/resource-access"),
        &query,
        crate::ResponseShape::Object,
    )
    .await?;
    let page: ResourceAccessDescription = serde_json::from_value(value.clone()).map_err(|_| {
        anyhow::anyhow!(
            "this agent-access version does not support the Broker's resource-access response; upgrade agent-access to match the Broker"
        )
    })?;
    if page.service != service {
        bail!("broker returned a different service");
    }
    if page
        .live_listings
        .iter()
        .any(|listing| listing.service != page.service)
    {
        bail!("broker returned a live listing for a different service");
    }
    Ok(value)
}

pub(crate) async fn actions_list(
    settings: &crate::ResolvedCliSettings,
    service: &str,
    resource: Option<&str>,
    resource_type: Option<&str>,
    prefix: Option<&str>,
    verbose: bool,
) -> Result<Value> {
    input(crate::validate_service_argument(service))?;
    input(crate::validate_discovery_prefix(prefix))?;
    nonempty("resource", resource)?;
    nonempty("resource type", resource_type)?;
    if resource_type.is_some() && resource.is_none() {
        return Err(InputError("resource type requires a resource".into()).into());
    }
    let mut query = Vec::new();
    if let Some(resource_type) = resource_type {
        query.push(("resourceType", resource_type.to_owned()));
    }
    if let Some(prefix) = prefix {
        query.push(("prefix", prefix.to_owned()));
    }
    if let Some(resource) = resource {
        query.push(("resource", resource.to_owned()));
    }
    let value = get(
        settings,
        &format!("/v1/services/{service}/actions"),
        &query,
        crate::ResponseShape::Object,
    )
    .await?;
    let selected: ActionList = serde_json::from_value(value.clone())
        .map_err(|_| anyhow::anyhow!("invalid broker action list"))?;
    if selected.service != service || selected.resource.as_deref() != resource {
        bail!("broker returned a different discovery query");
    }
    if selected
        .actions
        .iter()
        .any(|action| !agent_access_provider::is_action_name(action))
    {
        bail!("broker returned an invalid action name");
    }
    if !verbose {
        return Ok(value);
    }
    // The selected names are authoritative: a second snapshot may only drop names.
    let raw = service_describe(settings, service).await?;
    let mut definitions = crate::discovery_actions(crate::parse_discovery_service(raw)?)?;
    definitions.retain(|(action, _)| selected.actions.contains(&action.action));
    definitions.sort_by(|(left, _), (right, _)| left.action.cmp(&right.action));
    Ok(Value::Array(
        definitions.into_iter().map(|(_, raw)| raw).collect(),
    ))
}

pub(crate) async fn action_describe(
    settings: &crate::ResolvedCliSettings,
    view: &agent_access_core::mcp::McpView,
    service: &str,
    action: &str,
) -> Result<Value> {
    input(crate::validate_service_argument(service))?;
    if view.service().is_some_and(|selected| selected != service) {
        bail!("service is outside this MCP view");
    }
    input(crate::validate_action_argument(action))?;
    let raw = service_describe(settings, service).await?;
    let parsed = crate::parse_discovery_service(raw)?;
    let invoke = parsed.capabilities.surface == "invoke";
    let (capability, mut detail) = crate::discovery_actions(parsed)?
        .into_iter()
        .find(|(candidate, _)| candidate.action == action)
        .ok_or_else(|| InputError("action is not visible or does not exist".into()))?;
    if invoke {
        // Catalog visibility intentionally differs from /services for some token classes.
        let catalog_value = get(
            settings,
            "/v1/spec/catalog",
            &[],
            crate::ResponseShape::Object,
        )
        .await?;
        if catalog_value.get("version").and_then(Value::as_str)
            != Some(agent_access_core::API_CATALOG_VERSION)
        {
            bail!("unsupported broker catalog version");
        }
        let catalog: ApiCatalog = serde_json::from_value(catalog_value.clone())
            .map_err(|_| anyhow::anyhow!("invalid broker catalog"))?;
        let entry = catalog.services.iter().find(|candidate| candidate.service == service && candidate.surface == "invoke")
            .and_then(|service| service.actions.iter().find(|candidate| candidate.action == action))
            .ok_or_else(|| InputError("action detail is unavailable in the caller-visible catalog; use services describe for the raw definition or retry discovery".into()))?;
        let common: ActionCapabilities = serde_json::from_value(serde_json::to_value(entry)?)
            .context("invalid catalog action definition")?;
        if common != capability {
            return Err(InputError(
                "discovery data changed between requests; retry discovery".into(),
            )
            .into());
        }
        // Preserve public action details, excluding MCP projection source metadata.
        detail = catalog_value["services"]
            .as_array()
            .and_then(|services| services.iter().find(|value| value["service"] == service))
            .and_then(|service| service["actions"].as_array())
            .and_then(|actions| actions.iter().find(|value| value["action"] == action))
            .cloned()
            .context("invalid broker catalog action")?;
        // A helper can perform several broker reads. Rebuild from this fresh
        // catalog so the selected name and schema share one snapshot.
        let registry = agent_access_core::mcp::ToolRegistry::build(
            &catalog,
            view,
            agent_access_core::mcp::ProjectionMode::Stdio,
            agent_access_core::mcp::STDIO_MAX_CATALOG_BYTES,
        )?;
        if let Some(tool) = registry.action_detail(service, action) {
            detail["mcpTool"] = tool;
        } else if let Some(issue) = registry.action_unavailable(service, action) {
            detail["mcpToolUnavailable"] = json!(issue.code.as_str());
        }
    }
    if let Some(object) = detail.as_object_mut() {
        object.remove("scopedMcpName");
    }
    detail["service"] = json!(service);
    Ok(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    fn settings(server: &MockServer) -> crate::ResolvedCliSettings {
        crate::ResolvedCliSettings {
            url: server.uri(),
            request_timeout_ms: 30_000,
            tls: Default::default(),
            token: Some("discovery-token".into()),
            token_from_literal_arg: false,
            identity_header: "X-Agent-Access-Identity-Token".into(),
            identity_scheme: "raw".into(),
            allow_insecure_broker_http: false,
            read_content_format: Default::default(),
            output_format: Default::default(),
        }
    }
    fn service(surface: &str) -> Value {
        json!({"service":"gitlab","displayName":"GitLab","surface":surface,"availability":{"state":"available","requirements":[],"message":"Locally available"},"scopeTypes":["repository"],"actions":[{
            "action":"repo.fetch","readOnly":true,"description":"Fetch repository","requiredScopeTypes":["repository"],"credentialModes":["service"],"lookupRequired":false,
            "documentation":{"examples":["extended usage detail"]},
            "inputSchema":{"type":"object","properties":{"project":{"type":"string"}},"additionalProperties":false},"futureField":"preserved"
        }]})
    }
    fn catalog(raw: &Value) -> Value {
        let mut action = raw["actions"][0].clone();
        action["readOnly"] = json!(true);
        action["scopedMcpName"] = json!("OriginalToolName");
        action["io"] = json!({"type":"json"});
        action["responseKind"] = json!("response_envelope");
        action["exitPolicy"] = json!("invoke_decision");
        action["sensitiveOutputPointers"] = json!(["/result/token"]);
        action["responseFormats"] = json!(["json"]);
        let mut catalog =
            serde_json::to_value(agent_access_core::empty_catalog(json!({}))).unwrap();
        catalog["services"] = json!([{"scopedMcpReady":true,"service":raw["service"],"displayName":"GitLab","surface":"invoke","availability":{"state":"available","requirements":[],"message":"Locally available"},"scopeTypes":["repository"],"actions":[action]}]);
        catalog
    }
    async fn mount(server: &MockServer, route: &str, status: u16, body: Value) {
        Mock::given(method("GET"))
            .and(path(route))
            .and(header("X-Agent-Access-Identity-Token", "discovery-token"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(server)
            .await;
    }
    fn denial() -> Value {
        json!({"agentRequestId":"a","brokerRequestId":"b","decision":"deny","reasonCode":"service_action_denied"})
    }

    #[tokio::test]
    async fn describe_uses_complete_fresh_catalog_and_exact_native_projection() {
        let server = MockServer::start().await;
        let raw = service("invoke");
        let catalog = catalog(&raw);
        mount(&server, "/v1/services/gitlab", 200, raw).await;
        mount(&server, "/v1/spec/catalog", 200, catalog.clone()).await;
        let detail = action_describe(
            &settings(&server),
            &agent_access_core::mcp::McpView::Aggregate,
            "gitlab",
            "repo.fetch",
        )
        .await
        .unwrap();
        let action: agent_access_core::ApiActionSpec =
            serde_json::from_value(catalog["services"][0]["actions"][0].clone()).unwrap();
        assert_eq!(
            detail["mcpTool"]["inputSchema"],
            crate::mcp::tools::input_schema(&action)
        );
        assert_eq!(detail["mcpTool"]["name"], "gitlab_repo_fetch");
        assert_eq!(detail["io"], json!({"type":"json"}));
        assert_eq!(detail["sensitiveOutputPointers"], json!(["/result/token"]));
        assert_eq!(detail["futureField"], "preserved");
        assert_eq!(
            detail["documentation"],
            json!({"examples": ["extended usage detail"]})
        );
        assert!(detail["mcpTool"].get("documentation").is_none());
        assert_eq!(detail["service"], "gitlab");
        assert!(detail.get("scopedMcpName").is_none());
        for request in server.received_requests().await.unwrap() {
            assert!(request.url.query().is_none());
        }
    }

    #[tokio::test]
    async fn describe_checks_version_before_metadata_and_uses_the_complete_registry() {
        let server = MockServer::start().await;
        for version in [
            "agent-access.catalog.v1",
            agent_access_core::API_CATALOG_VERSION,
        ] {
            for missing_action_name in [false, true] {
                server.reset().await;
                mount(&server, "/v1/services/gitlab", 200, service("invoke")).await;
                let mut value = catalog(&service("invoke"));
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
                mount(&server, "/v1/spec/catalog", 200, value).await;
                let error = action_describe(
                    &settings(&server),
                    &agent_access_core::mcp::McpView::Aggregate,
                    "gitlab",
                    "repo.fetch",
                )
                .await
                .unwrap_err();
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
        server.reset().await;
        mount(&server, "/v1/services/gitlab", 200, service("invoke")).await;
        let mut value = catalog(&service("invoke"));
        let duplicate = value["services"][0].clone();
        value["services"].as_array_mut().unwrap().push(duplicate);
        mount(&server, "/v1/spec/catalog", 200, value).await;
        assert_eq!(
            action_describe(
                &settings(&server),
                &agent_access_core::mcp::McpView::Aggregate,
                "gitlab",
                "repo.fetch"
            )
            .await
            .unwrap_err()
            .to_string(),
            "runtime catalog has duplicate action identities"
        );
    }

    #[tokio::test]
    async fn describe_reports_safe_naming_issues_and_keeps_scoped_names_usable() {
        for (service_id, action_id, code) in [
            ("gitlab", "repo.fetch".to_owned(), "name_conflict"),
            ("gitlab", "a".repeat(122), "name_too_long"),
            ("services", "list".to_owned(), "reserved_name"),
        ] {
            let server = MockServer::start().await;
            let mut raw = service("invoke");
            raw["service"] = json!(service_id);
            raw["actions"][0]["action"] = json!(action_id);
            let mut value = catalog(&raw);
            if code == "name_conflict" {
                let mut other = value["services"][0]["actions"][0].clone();
                other["action"] = json!("repo_fetch");
                other["scopedMcpName"] = json!("OtherToolName");
                value["services"][0]["actions"]
                    .as_array_mut()
                    .unwrap()
                    .push(other);
            }
            mount(&server, &format!("/v1/services/{service_id}"), 200, raw).await;
            mount(&server, "/v1/spec/catalog", 200, value).await;
            let detail = action_describe(
                &settings(&server),
                &agent_access_core::mcp::McpView::Aggregate,
                service_id,
                &action_id,
            )
            .await
            .unwrap();
            assert_eq!(detail["action"], action_id);
            assert!(detail.get("mcpTool").is_none(), "{detail}");
            assert_eq!(detail["mcpToolUnavailable"], code, "{detail}");
            assert!(!detail.to_string().contains("OtherToolName"));
            let scoped = action_describe(
                &settings(&server),
                &agent_access_core::mcp::McpView::Service(service_id.into()),
                service_id,
                &action_id,
            )
            .await
            .unwrap();
            assert_eq!(scoped["mcpTool"]["name"], "OriginalToolName");
            assert!(scoped.get("mcpToolUnavailable").is_none());
        }
    }

    #[tokio::test]
    async fn describe_distinguishes_absent_unavailable_changed_and_http_failure() {
        let server = MockServer::start().await;
        mount(&server, "/v1/services/gitlab", 200, service("invoke")).await;
        let absent = action_describe(
            &settings(&server),
            &agent_access_core::mcp::McpView::Aggregate,
            "gitlab",
            "repo.push",
        )
        .await
        .unwrap_err();
        assert_eq!(
            absent.to_string(),
            "action is not visible or does not exist"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        let empty = serde_json::to_value(agent_access_core::empty_catalog(json!({}))).unwrap();
        mount(&server, "/v1/spec/catalog", 200, empty).await;
        let missing = action_describe(
            &settings(&server),
            &agent_access_core::mcp::McpView::Aggregate,
            "gitlab",
            "repo.fetch",
        )
        .await
        .unwrap_err();
        assert!(
            missing
                .to_string()
                .contains("unavailable in the caller-visible catalog")
        );
        server.reset().await;
        mount(&server, "/v1/services/gitlab", 200, service("invoke")).await;
        let mut changed = catalog(&service("invoke"));
        changed["services"][0]["actions"][0]["inputSchema"] = json!({"type":"object"});
        mount(&server, "/v1/spec/catalog", 200, changed).await;
        let skew = action_describe(
            &settings(&server),
            &agent_access_core::mcp::McpView::Aggregate,
            "gitlab",
            "repo.fetch",
        )
        .await
        .unwrap_err();
        assert!(skew.to_string().contains("changed between requests"));
        server.reset().await;
        mount(&server, "/v1/services/gitlab", 200, service("invoke")).await;
        mount(&server, "/v1/spec/catalog", 403, denial()).await;
        let error = action_describe(
            &settings(&server),
            &agent_access_core::mcp::McpView::Aggregate,
            "gitlab",
            "repo.fetch",
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<BrokerFailure>().unwrap().body,
            denial()
        );
    }

    #[tokio::test]
    async fn noninvoke_describe_does_not_fetch_catalog() {
        for surface in ["gateway"] {
            let server = MockServer::start().await;
            mount(&server, "/v1/services/gitlab", 200, service(surface)).await;
            let detail = action_describe(
                &settings(&server),
                &agent_access_core::mcp::McpView::Aggregate,
                "gitlab",
                "repo.fetch",
            )
            .await
            .unwrap();
            assert!(detail.get("mcpTool").is_none());
            assert_eq!(detail["futureField"], "preserved");
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn verbose_intersection_cannot_restore_unselected_actions_and_propagates_second_failure()
    {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/services/gitlab/actions"))
            .and(query_param("resource", "team/repo"))
            .and(query_param("prefix", "repo."))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"service":"gitlab","resource":"team/repo","actions":["repo.missing"]}),
            ))
            .mount(&server)
            .await;
        mount(&server, "/v1/services/gitlab", 200, service("gateway")).await;
        assert_eq!(
            actions_list(
                &settings(&server),
                "gitlab",
                Some("team/repo"),
                None,
                Some("repo."),
                true
            )
            .await
            .unwrap(),
            json!([])
        );
        server.reset().await;
        mount(
            &server,
            "/v1/services/gitlab/actions",
            200,
            json!({"service":"gitlab","actions":["repo.fetch"]}),
        )
        .await;
        mount(&server, "/v1/services/gitlab", 403, denial()).await;
        let error = actions_list(&settings(&server), "gitlab", None, None, None, true)
            .await
            .unwrap_err();
        assert_eq!(error.downcast_ref::<BrokerFailure>().unwrap().status, 403);
    }

    #[tokio::test]
    async fn resource_page_is_returned_once_with_encoded_filters_and_cursor() {
        let server = MockServer::start().await;
        let page = json!({"service":"gitlab","executionContext":"default","availability":{"state":"available","requirements":[],"message":"Locally available"},"coverageSemantics":"single_target","access":[{"action":"project.view","scope":"resource","resourceType":"git_repository","enforcement":"request","coverage":[{"selector":{"kind":"all"},"restricted":false}]}],"registeredResources":{"source":"broker_configuration","items":[{"id":"r","type":"git_repository","value":"team/repo","displayName":"Repository"}],"nextCursor":"opaque:+/="},"liveListings":[{"service":"gitlab","action":"project.list","resourceType":"git_repository"}]});
        Mock::given(method("GET"))
            .and(path("/v1/services/gitlab/resource-access"))
            .and(query_param("action", "project.view"))
            .and(query_param("resourceType", "git_repository"))
            .and(query_param("prefix", "team/"))
            .and(query_param("limit", "1"))
            .and(query_param("cursor", "opaque:+/="))
            .respond_with(ResponseTemplate::new(200).set_body_json(page.clone()))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            resource_access_describe(
                &settings(&server),
                "gitlab",
                Some("project.view"),
                Some("git_repository"),
                Some("team/"),
                Some(1),
                Some("opaque:+/=")
            )
            .await
            .unwrap(),
            page
        );
    }

    #[tokio::test]
    async fn resource_access_rejects_live_listing_links_to_another_service() {
        let server = MockServer::start().await;
        mount(
            &server,
            "/v1/services/gitlab/resource-access",
            200,
            json!({
                "service":"gitlab", "executionContext":"default",
                "availability":{"state":"available","requirements":[],"message":"Locally available"},
                "coverageSemantics":"single_target", "access":[],
                "registeredResources":{"source":"broker_configuration","items":[],"nextCursor":null},
                "liveListings":[{"service":"different","action":"project.list","resourceType":"git_repository"}]
            }),
        ).await;
        let error =
            resource_access_describe(&settings(&server), "gitlab", None, None, None, None, None)
                .await
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "broker returned a live listing for a different service"
        );
    }

    #[tokio::test]
    async fn resource_access_unknown_contract_reports_how_to_upgrade() {
        let server = MockServer::start().await;
        mount(
            &server,
            "/v1/services/gitlab/resource-access",
            200,
            json!({
                "service":"gitlab", "executionContext":"default",
                "availability":{"state":"available","requirements":[],"message":"Locally available"},
                "coverageSemantics":"single_target",
                "access":[{"action":"project.view","scope":"resource","resourceType":"git_repository",
                    "enforcement":"future_mode","coverage":[]}],
                "registeredResources":{"source":"broker_configuration","items":[],"nextCursor":null}
            }),
        ).await;
        let error =
            resource_access_describe(&settings(&server), "gitlab", None, None, None, None, None)
                .await
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "this agent-access version does not support the Broker's resource-access response; upgrade agent-access to match the Broker"
        );
    }
}
