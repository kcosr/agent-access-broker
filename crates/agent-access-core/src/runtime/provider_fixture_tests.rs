//! Test-support provider fixtures replace only the providers of configured
//! native kinds they name, in every generation, and never widen what the
//! configuration admits.
use super::tests::base_fake_config;
use super::*;
use crate::ProvidersConfig;
use crate::test_support::ProviderFixtures;
use std::sync::atomic::AtomicUsize;

fn jira_configured(mut config: BrokerConfig) -> BrokerConfig {
    config
        .providers
        .insert(agent_access_jira::JiraProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
            attachments: Default::default(),
            content: Default::default(),
            search: Default::default(),
            listing: Default::default(),
            comments: Default::default(),
            issue_links: Default::default(),
        });
    config
}

fn fixture_error(config: BrokerConfig, fixtures: ProviderFixtures) -> Vec<String> {
    match BrokerRuntime::new_with_provider_fixtures(
        config,
        Arc::new(AuditRuntimeRegistry::new()),
        fixtures,
    ) {
        Ok(_) => panic!("expected the provider fixture to be rejected"),
        Err(RuntimeError::Config(ConfigError::Invalid { errors })) => errors,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

#[test]
fn a_fixture_replaces_its_kind_in_every_generation_and_others_are_built() {
    let built = Arc::new(AtomicUsize::new(0));
    let served = Arc::new(agent_access_fake::FakeProvider);
    let mut fixtures = ProviderFixtures::new();
    assert!(fixtures.insert("fake", {
        let built = Arc::clone(&built);
        let served = Arc::clone(&served);
        move |context| {
            built.fetch_add(1, Ordering::SeqCst);
            assert_eq!(context.descriptor().service, "fake");
            assert_eq!(
                context.build_context().limits().max_http_body_bytes,
                ProviderLimits::default().max_http_body_bytes
            );
            ServiceProvider::new(context.descriptor().clone(), served.clone())
        }
    }));
    assert!(!fixtures.insert("fake", |context| {
        ServiceProvider::new(
            context.descriptor().clone(),
            Arc::new(agent_access_fake::FakeProvider),
        )
    }));
    let config = jira_configured(base_fake_config());
    let runtime = BrokerRuntime::new_with_provider_fixtures(
        config.clone(),
        Arc::new(AuditRuntimeRegistry::new()),
        fixtures,
    )
    .unwrap();
    assert_eq!(built.load(Ordering::SeqCst), 1);
    let fake: Arc<dyn Provider> = served.clone();
    assert!(Arc::ptr_eq(&runtime.providers["fake"], &fake));
    assert!(runtime.providers.contains_key("jira"));

    let candidate = BrokerRuntime::new_for_reload(config, &runtime).unwrap();
    assert_eq!(built.load(Ordering::SeqCst), 2);
    assert!(Arc::ptr_eq(&candidate.providers["fake"], &fake));

    // A generation that no longer configures the kind does not use it.
    let mut without_fake = base_fake_config();
    without_fake.providers = ProvidersConfig::new(Arc::clone(without_fake.providers.registry()));
    without_fake.credentials.service.clear();
    without_fake.policy.grants.clear();
    let unconfigured = BrokerRuntime::new_for_reload(without_fake, &candidate).unwrap();
    assert_eq!(built.load(Ordering::SeqCst), 2);
    assert!(!unconfigured.providers.contains_key("fake"));
}

#[test]
fn a_fixture_can_serve_the_registration_s_own_provider() {
    let mut fixtures = ProviderFixtures::new();
    fixtures.insert("fake", |context| context.registered_provider().unwrap());
    let runtime = BrokerRuntime::new_with_provider_fixtures(
        base_fake_config(),
        Arc::new(AuditRuntimeRegistry::new()),
        fixtures,
    )
    .unwrap();
    assert_eq!(runtime.services["fake"].service, "fake");
    assert!(runtime.providers.contains_key("fake"));
}

#[test]
fn a_fixture_must_name_a_selected_and_configured_kind_at_startup() {
    let mut unselected = ProviderFixtures::new();
    unselected.insert("teams", |context| {
        ServiceProvider::new(
            context.descriptor().clone(),
            Arc::new(agent_access_fake::FakeProvider),
        )
    });
    assert_eq!(
        fixture_error(base_fake_config(), unselected),
        ["provider fixture teams names no selected native provider"]
    );

    let mut unconfigured = ProviderFixtures::new();
    unconfigured.insert("jira", |context| {
        ServiceProvider::new(
            context.descriptor().clone(),
            Arc::new(agent_access_fake::FakeProvider),
        )
    });
    assert_eq!(
        fixture_error(base_fake_config(), unconfigured),
        ["provider fixture jira has no [providers.jira] configuration"]
    );
}

#[test]
fn a_fixture_cannot_serve_another_service() {
    let mut fixtures = ProviderFixtures::new();
    fixtures.insert("jira", |_| agent_access_fake::fake_service_provider());
    assert_eq!(
        fixture_error(jira_configured(base_fake_config()), fixtures),
        ["provider fixture jira serves service fake"]
    );
}

#[test]
fn a_fixture_does_not_bypass_configuration_validation() {
    let mut fixtures = ProviderFixtures::new();
    fixtures.insert("fake", |_| agent_access_fake::fake_service_provider());
    let mut config = base_fake_config();
    config.deployment.enable_fake_service = false;
    let errors = fixture_error(config, fixtures);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("enable_fake_service")),
        "{errors:?}"
    );
}
