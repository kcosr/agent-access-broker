//! Naming omissions leave the real HTTP MCP session and unaffected tools usable.
use super::*;
use agent_access_provider::{
    BackendConfig, BuildContext, EgressProxyConfig, ProviderBuildError, ValidationContext,
};

#[derive(Clone, Debug)]
struct NamingBackend {
    collision: bool,
}

impl BackendConfig for NamingBackend {
    fn kind(&self) -> &'static str {
        "fake"
    }

    fn validate(&self, _context: &ValidationContext<'_>, _errors: &mut Vec<String>) {}

    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        let echo = descriptor.actions[0].clone();
        for name in [
            "item.read".into(),
            "file.read".into(),
            "file_read".into(),
            "a".repeat(124),
        ] {
            let mut action = echo.clone();
            action.action = name;
            if action.action == "file_read" {
                action = action.raw_download();
            }
            descriptor.actions.push(action);
        }
        if self.collision {
            let mut action = echo;
            action.action = "item_read".into();
            descriptor.actions.push(action);
        }
        descriptor
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        Vec::new()
    }

    fn build(&self, _host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(self.clone()))
    }
}

#[async_trait::async_trait]
impl Provider for NamingBackend {
    fn resolve_scopes(
        &self,
        _action: &str,
        inputs: &Value,
    ) -> Result<ResourceScopes, ProviderError> {
        agent_access_fake::FakeProvider.resolve_scopes("echo", inputs)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        agent_access_fake::FakeProvider.invoke(request).await
    }
}

fn configure(config: &mut BrokerConfig, collision: bool) {
    let backend = NamingBackend { collision };
    config.policy.grants[0].actions = backend
        .descriptor()
        .actions
        .into_iter()
        .map(|action| action.action)
        .collect();
    config.providers.insert(backend);
}

#[tokio::test]
async fn aggregate_omissions_describe_safely_and_refresh_after_a_conflict_is_removed() {
    let fixture = Fixture::new(|config| configure(config, true));
    let session = fixture.initialize().await;
    let listed = fixture.rpc(&session, 2, "tools/list", json!({})).await;
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 6, "{listed}");
    assert!(tools.iter().any(|tool| tool["name"] == "fake_echo"));
    for name in [
        "fake_item_read".to_owned(),
        "fake_file_read".to_owned(),
        format!("fake_{}", "a".repeat(124)),
    ] {
        assert!(!tools.iter().any(|tool| tool["name"] == name));
        let rejected = fixture
            .call(
                &session,
                3,
                &name,
                json!({"inputs":{"project":"TEST","message":"must not run"}}),
            )
            .await;
        assert_eq!(rejected["error"]["code"], -32602, "{rejected}");
    }
    for (action, code) in [
        ("item.read".to_owned(), "name_conflict"),
        ("item_read".to_owned(), "name_conflict"),
        ("file.read".to_owned(), "name_conflict"),
        ("a".repeat(124), "name_too_long"),
    ] {
        let described = fixture
            .call(
                &session,
                4,
                "actions_describe",
                json!({"service":"fake","action":action}),
            )
            .await;
        let detail = structured(&described);
        assert_eq!(detail["action"], action);
        assert!(detail.get("mcpTool").is_none(), "{described}");
        assert_eq!(detail["mcpToolUnavailable"], code, "{described}");
        assert!(detail["mcpToolUnavailable"].is_string());
    }
    let file = fixture
        .call(
            &session,
            5,
            "actions_describe",
            json!({"service":"fake","action":"file_read"}),
        )
        .await;
    assert!(structured(&file).get("mcpTool").is_none());
    assert!(structured(&file).get("mcpToolUnavailable").is_none());
    let allowed = fixture
        .call(
            &session,
            6,
            "fake_echo",
            json!({"inputs":{"project":"TEST","message":"still usable"}}),
        )
        .await;
    assert_eq!(structured(&allowed)["decision"], "allow");

    publish_reload(&fixture, |config| configure(config, false));
    let refreshed = fixture.rpc(&session, 7, "tools/list", json!({})).await;
    assert!(
        refreshed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "fake_item_read")
    );
    let detail = fixture
        .call(
            &session,
            8,
            "actions_describe",
            json!({"service":"fake","action":"item.read"}),
        )
        .await;
    assert_eq!(structured(&detail)["mcpTool"]["name"], "fake_item_read");
    assert!(structured(&detail).get("mcpToolUnavailable").is_none());
    let allowed = fixture
        .call(
            &session,
            9,
            "fake_item_read",
            json!({"inputs":{"project":"TEST","message":"newly available"}}),
        )
        .await;
    assert_eq!(structured(&allowed)["decision"], "allow");
    assert_eq!(
        read_audit_records(&fixture.audit_path)
            .iter()
            .filter(|record| record["decision"] == "allow")
            .count(),
        2
    );
}
