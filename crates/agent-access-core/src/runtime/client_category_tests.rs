//! The runtime builds each native backend's upstream clients in the category
//! of the registration its configuration table selected: only an enabled
//! development-only registration may receive the direct loopback route.
use super::*;
use crate::{BackendRegistry, ProvidersConfig};
use agent_access_provider::{BackendConfig, BackendRegistration};

const SERVICE: &str = "loopback_fixture";

static DEVELOPMENT_REGISTRATION: BackendRegistration = BackendRegistration {
    kind: SERVICE,
    resource_types: &[],
    parse: parse_backend_config::<LoopbackFixture>,
    development_only: true,
};
static PRODUCTION_REGISTRATION: BackendRegistration = BackendRegistration {
    kind: SERVICE,
    resource_types: &[],
    parse: parse_backend_config::<LoopbackFixture>,
    development_only: false,
};

/// A backend whose one client asks for the direct loopback route, labeled
/// and identified like the host's OAuth clients.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LoopbackFixture {}

impl BackendConfig for LoopbackFixture {
    fn kind(&self) -> &'static str {
        SERVICE
    }
    fn validate(&self, _: &ValidationContext<'_>, _: &mut Vec<String>) {}
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor {
            service: SERVICE.into(),
            display_name: "Loopback fixture".into(),
            surface: ServiceSurface::Invoke,
            resource_scopes: BTreeMap::new(),
            actions: vec![
                ActionDescriptor::new(
                    "ping",
                    "Fixture action",
                    json!({"type":"object","additionalProperties":false}),
                )
                .credential_modes(["service"]),
            ],
            credentials: CredentialDescriptor::without_execution_credential(),
            presentation_body_limit: None,
        }
    }
    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        vec![]
    }
    fn build(&self, host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        let base = Url::parse("http://127.0.0.1:9/").unwrap();
        UpstreamClient::build(
            UpstreamClientSpec {
                label: "oauth.registrations.stub",
                provider: "oauth",
                base: &base,
                egress: EgressDeclaration::LiteralLoopback,
                allowed_upstream_hosts: &[format!("{base}**")],
                profile: ClientProfile::Request,
                status_reasons: &[],
            },
            host.clients(),
        )?;
        Ok(Arc::new(agent_access_fake::FakeProvider))
    }
}

fn config(registration: &'static BackendRegistration, environment: &str) -> BrokerConfig {
    let mut config = tests::base_fake_config();
    config.deployment.environment = environment.into();
    config.credentials = Default::default();
    config.policy.resources.clear();
    config.policy.resource_groups.clear();
    config.policy.grants.clear();
    config.providers =
        ProvidersConfig::new(Arc::new(BackendRegistry::new([registration]).unwrap()))
            .with(LoopbackFixture {});
    config
}

#[test]
fn an_enabled_development_registration_receives_the_loopback_route() {
    BrokerRuntime::new(config(&DEVELOPMENT_REGISTRATION, "development")).unwrap();
}

#[test]
fn a_production_registration_is_denied_the_loopback_route_whatever_its_label() {
    let error = match BrokerRuntime::new(config(&PRODUCTION_REGISTRATION, "development")) {
        Ok(_) => panic!("a production registration must not receive the loopback route"),
        Err(error) => error,
    };
    assert!(
        matches!(
            &error,
            RuntimeError::Config(ConfigError::Invalid { errors })
                if errors.len() == 1
                    && errors[0].contains("only OAuth and enabled development fixtures")
        ),
        "{error:?}"
    );
}
