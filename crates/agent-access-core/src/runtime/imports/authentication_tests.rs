//! Import eligibility and the import-authentication projection come from the
//! selected registration's OAuth companion, never from a dialect ID.
use super::*;
use crate::BackendRegistry;
use crate::imports::{
    ImportOAuthCompanion, ImportedAdapterRegistration, ImportedBindingStatus,
    ImportedCredentialBinding, ImportedDiscovery, ImportedDiscoveryAuthentication,
    imported_adapter_registration,
};
use crate::oauth::tests::DEFAULT_SCOPE_DIALECT;
use agent_access_fake::STUB_OAUTH_DIALECT;
use agent_access_provider::{OAuthAdapter, OAuthPermissionProfile, OAuthRegistrationConfig};

#[derive(Debug)]
struct SyntheticImport(&'static str);
static COMPANION_IMPORT: SyntheticImport = SyntheticImport("fixture_import");
static STATIC_IMPORT: SyntheticImport = SyntheticImport("static_import");

#[async_trait::async_trait]
impl ImportedAdapter for SyntheticImport {
    fn kind(&self) -> &'static str {
        self.0
    }
    fn development_only(&self) -> bool {
        false
    }
    fn validate_action(&self, _: &ImportedActionDefinition) -> Result<(), String> {
        unreachable!("eligibility never validates actions")
    }
    fn scoped_mcp_name(&self, _: &ImportedActionDefinition) -> Result<String, String> {
        unreachable!("eligibility never names actions")
    }
    fn build(
        &self,
        _: &ImportedServiceDefinition,
        _: &[ImportedActionDefinition],
        _: Option<ExecutionCredential>,
        _: &BuildContext<'_>,
    ) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        unreachable!("eligibility never builds providers")
    }
    async fn discover(
        &self,
        _: &ImportedServiceDefinition,
        _: &ImportedDiscoveryAuthentication,
        _: Option<ExecutionCredential>,
        _: &BuildContext<'_>,
    ) -> Result<ImportedDiscovery, ProviderError> {
        unreachable!("eligibility never discovers")
    }
}

/// The companion derives the approved resource from the issuer, not from an
/// adapter setting named `resource`; it rejects non-HTTPS issuers.
fn records_resource(registration: &OAuthRegistrationConfig) -> Option<String> {
    registration
        .base_url
        .starts_with("https://")
        .then(|| format!("{}/records", registration.base_url.trim_end_matches('/')))
}

fn companion_import() -> ImportedAdapterRegistration {
    imported_adapter_registration(
        agent_access_provider::module_metadata!(),
        &COMPANION_IMPORT,
        Some(ImportOAuthCompanion {
            dialect: &STUB_OAUTH_DIALECT,
            approved_resource: records_resource,
        }),
    )
}

const ENDPOINT: &str = "https://auth.example.test/records";

fn registration(adapter: &str, base_url: &str) -> OAuthRegistrationConfig {
    OAuthRegistrationConfig {
        adapter: OAuthAdapter::new(adapter),
        base_url: base_url.into(),
        redirect_uri: "https://broker.example.test/v1/oauth/callback/records".into(),
        client_id: "broker".into(),
        client_secret_ref: "env:RECORDS_SECRET".into(),
        adapter_settings: BTreeMap::new(),
        client_auth: Default::default(),
        encoding: Default::default(),
        rotation: Default::default(),
        allow_insecure_loopback: false,
        permission_profiles: BTreeMap::from([(
            "read".into(),
            OAuthPermissionProfile {
                scope_mode: Default::default(),
                scopes: Some(vec!["records.read".into()]),
                audience: ENDPOINT.into(),
                target: ENDPOINT.into(),
            },
        )]),
    }
}

fn config() -> BrokerConfig {
    let registry = BackendRegistry::empty()
        .with_oauth_dialects([&DEFAULT_SCOPE_DIALECT])
        .unwrap()
        .with_imported_adapters([
            companion_import(),
            imported_adapter_registration(
                agent_access_provider::module_metadata!(),
                &STATIC_IMPORT,
                None,
            ),
        ])
        .unwrap();
    let mut config = crate::parse_broker_config_raw(
        "import-authentication.toml",
        "[identity]\nmode = \"anonymous\"\nauthority = \"toml\"\n[policy]\nauthority = \"toml\"\ndefault_decision = \"deny\"\n",
        &Arc::new(BackendRegistry::empty()),
    )
    .unwrap();
    config.providers = crate::ProvidersConfig::new(Arc::new(registry));
    config.oauth.registrations = BTreeMap::from([
        (
            "records".into(),
            registration("stub", "https://auth.example.test"),
        ),
        (
            "insecure".into(),
            registration("stub", "http://127.0.0.1:8099"),
        ),
        (
            "unrelated".into(),
            registration("default_scope_fixture", "https://auth.example.test"),
        ),
    ]);
    config
}

fn definition(kind: &str) -> ImportedServiceDefinition {
    ImportedServiceDefinition {
        service: "records".into(),
        display_name: "Records".into(),
        adapter_kind: kind.into(),
        endpoint: ENDPOINT.into(),
        connection_settings: BTreeMap::new(),
        execution_bindings: vec![],
        discovery: ImportedDiscoveryCredential::Execution,
        transport_auth: false,
        invocation_limit: None,
    }
}

fn binding(adapter: &str, registration: &str) -> ImportedCredentialBinding {
    ImportedCredentialBinding {
        owner_mode: ImportedCredentialMode::PerUser,
        mechanism: ImportedAuthMechanism::Oauth,
        delivery: ImportedCredentialDelivery::Bearer,
        status: ImportedBindingStatus::Configured,
        adapter_id: Some(adapter.into()),
        registration_id: Some(registration.into()),
        profile: Some("read".into()),
    }
}

#[test]
fn oauth_eligibility_comes_from_the_selected_import_companion() {
    let config = config();
    let allowed = |definition: &ImportedServiceDefinition, binding: &ImportedCredentialBinding| {
        oauth_binding_allowed(&config, definition, binding)
    };
    let fixture = definition("fixture_import");
    assert!(allowed(&fixture, &binding("stub", "records")));
    // Static bindings never need a companion.
    assert!(allowed(
        &definition("static_import"),
        &ImportedCredentialBinding::token(
            ImportedCredentialMode::PerUser,
            ImportedCredentialDelivery::Bearer,
        ),
    ));
    // The same binding without an import role: an import kind with no
    // companion, or a selected dialect that is not this kind's companion.
    assert!(!allowed(
        &definition("static_import"),
        &binding("stub", "records")
    ));
    assert!(!allowed(
        &definition("unselected_import"),
        &binding("stub", "records")
    ));
    assert!(!allowed(
        &fixture,
        &binding("default_scope_fixture", "unrelated")
    ));
    assert!(!allowed(
        &fixture,
        &binding("default_scope_fixture", "records")
    ));
    assert!(!allowed(&fixture, &binding("stub", "unrelated")));
    assert!(!allowed(&fixture, &binding("stub", "removed")));
    // The companion rejects the registration, so it approves no resource.
    assert!(!allowed(&fixture, &binding("stub", "insecure")));
    // Endpoint, approved resource, target and audience must all match.
    let mut moved = fixture.clone();
    moved.endpoint = "https://auth.example.test/other".into();
    assert!(!allowed(&moved, &binding("stub", "records")));
    for field in ["target", "audience"] {
        let mut config = config.clone();
        let profile = config
            .oauth
            .registrations
            .get_mut("records")
            .unwrap()
            .permission_profiles
            .get_mut("read")
            .unwrap();
        if field == "target" {
            profile.target = "https://auth.example.test/other".into();
        } else {
            profile.audience = "https://auth.example.test/other".into();
        }
        assert!(
            !oauth_binding_allowed(&config, &fixture, &binding("stub", "records")),
            "{field}"
        );
    }
    let mut unknown_profile = binding("stub", "records");
    unknown_profile.profile = Some("write".into());
    assert!(!allowed(&fixture, &unknown_profile));
}

#[test]
fn the_projection_groups_approved_registrations_by_import_kind() {
    let config = config();
    assert_eq!(
        import_authentication(&config),
        json!([{
            "importKind": "fixture_import",
            "dialectId": "stub",
            "registrations": [{
                "id": "records",
                "issuer": "https://auth.example.test",
                "resource": ENDPOINT,
                "permissionProfiles": [
                    {"id": "read", "scopeMode": "explicit", "scopes": ["records.read"]}
                ],
            }],
        }])
    );
    let mut none = config.clone();
    none.oauth.registrations.clear();
    assert_eq!(
        import_authentication(&none),
        json!([{"importKind": "fixture_import", "dialectId": "stub", "registrations": []}])
    );
    let mut empty = config;
    empty.providers = crate::ProvidersConfig::new(Arc::new(BackendRegistry::empty()));
    assert_eq!(import_authentication(&empty), json!([]));
}

#[test]
fn a_companion_dialect_selected_again_is_a_duplicate() {
    let duplicate = ["OAuth dialect stub is registered more than once"];
    assert_eq!(
        BackendRegistry::empty()
            .with_imported_adapters([companion_import()])
            .unwrap()
            .with_oauth_dialects([&STUB_OAUTH_DIALECT])
            .unwrap_err(),
        duplicate
    );
    assert_eq!(
        BackendRegistry::empty()
            .with_oauth_dialects([&STUB_OAUTH_DIALECT])
            .unwrap()
            .with_imported_adapters([companion_import()])
            .unwrap_err(),
        duplicate
    );
    let registry = BackendRegistry::empty()
        .with_imported_adapters([companion_import()])
        .unwrap();
    assert_eq!(
        registry.oauth_dialect_ids().collect::<Vec<_>>(),
        ["stub"],
        "selecting the import selects its companion dialect"
    );
    assert_eq!(
        registry
            .with_imported_adapters([companion_import()])
            .unwrap_err(),
        ["import adapter kind fixture_import is registered more than once"]
    );
}
