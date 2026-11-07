//! Common host-owned gateway settings and registry-driven protocol parsing.
use crate::{BackendRegistry, EgressProxyConfig, GatewayUpstreamTokenAuth};
use agent_access_provider::GatewayServiceContext;
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    #[serde(default)]
    pub allow_forwarded_identity: bool,
    pub kind: String,
    pub display_name: String,
    #[serde(default)]
    pub broker_hosts: Vec<String>,
    pub upstream_base_url: String,
    #[serde(default)]
    pub allowed_upstream_hosts: Vec<String>,
    pub egress_proxy: Option<EgressProxyConfig>,
    #[serde(default)]
    pub auth_modes: Vec<String>,
    #[serde(default = "default_basic_broker_token_username")]
    pub basic_broker_token_username: String,
    #[serde(default)]
    pub credential_modes: Vec<String>,
    /// How the gateway presents a token-kind upstream credential.
    #[serde(default)]
    pub upstream_token_auth: GatewayUpstreamTokenAuth,
    #[serde(default = "default_gateway_redirect_policy")]
    pub redirect_policy: String,
    pub request_body_max_bytes: Option<u64>,
    pub response_body_max_bytes: Option<u64>,
    pub streaming_idle_timeout_ms: Option<u64>,
    #[serde(default = "default_gateway_correlation_headers")]
    pub correlation_headers: bool,
    /// Strictly parsed by the selected linked gateway module.
    #[serde(flatten)]
    pub protocol_fields: BTreeMap<String, toml::Value>,
}

impl GatewayConfig {
    pub fn new(
        kind: impl Into<String>,
        display_name: impl Into<String>,
        upstream_base_url: impl Into<String>,
    ) -> Self {
        Self {
            allow_forwarded_identity: false,
            kind: kind.into(),
            display_name: display_name.into(),
            broker_hosts: Vec::new(),
            upstream_base_url: upstream_base_url.into(),
            allowed_upstream_hosts: Vec::new(),
            egress_proxy: None,
            auth_modes: Vec::new(),
            basic_broker_token_username: default_basic_broker_token_username(),
            credential_modes: Vec::new(),
            upstream_token_auth: GatewayUpstreamTokenAuth::default(),
            redirect_policy: default_gateway_redirect_policy(),
            request_body_max_bytes: None,
            response_body_max_bytes: None,
            streaming_idle_timeout_ms: None,
            correlation_headers: true,
            protocol_fields: BTreeMap::new(),
        }
    }
    pub fn service_context(&self, service: &str) -> GatewayServiceContext {
        GatewayServiceContext::new(service, &self.display_name, &self.upstream_base_url)
            .with_broker_hosts(self.broker_hosts.clone())
            .with_credential_modes(self.credential_modes.clone())
            .with_auth_modes(self.auth_modes.clone())
    }
    pub fn module_config(
        &self,
        registry: &BackendRegistry,
    ) -> Result<Arc<dyn agent_access_provider::GatewayConfig>, String> {
        let registration = registry.gateway(&self.kind).ok_or_else(|| {
            format!(
                "gateway kind {} is not selected in this assembly",
                self.kind
            )
        })?;
        registration.parse_config(toml::Value::Table(
            self.protocol_fields.clone().into_iter().collect(),
        ))
    }
}
fn default_basic_broker_token_username() -> String {
    "agent-access".into()
}
fn default_gateway_redirect_policy() -> String {
    "none".into()
}
fn default_gateway_correlation_headers() -> bool {
    true
}
