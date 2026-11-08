//! Canonical policy contract captured from the pre-extraction Git gateway.
//! The fixture's source commit/hashes identify its original factory and parser.
use agent_access_git_http::GIT_HTTP_GATEWAY;
use agent_access_provider::{GatewayServiceContext, ServiceDescriptor};
use serde_json::{Value, json};

fn descriptor_projection(descriptor: &ServiceDescriptor) -> serde_json::Value {
    let mut capabilities = serde_json::to_value(descriptor.capabilities()).unwrap();
    capabilities
        .as_object_mut()
        .unwrap()
        .remove("credentialVerificationSupported");
    let credentials = &descriptor.credentials;
    json!({"capabilities": capabilities,
        "credentials": {
            "executionRequired": credentials.execution_required,
            "delegated": credentials.delegated.as_ref().map(|value| value.description),
            "serviceKinds": credentials.service_kinds,
            "profiles": credentials.profiles.iter().map(|profile| json!({
                "name": profile.name, "kind": profile.kind, "label": profile.label, "routeBound": profile.route_bound,
            })).collect::<Vec<_>>(),
            "verificationInputs": credentials.verification_inputs,
        },
        "upstreamAuthority": descriptor.upstream_authority.as_ref().map(|value| json!({
            "origin": value.origin(), "instancePath": value.instance_path(),
            "tenant": value.tenant(), "tenantGateway": value.tenant_gateway(),
        })),
        "presentationBodyLimit": descriptor.presentation_body_limit,
    })
}

#[test]
fn linked_git_descriptors_match_the_frozen_policy_contract() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/git-config-descriptor-baseline.json")).unwrap();
    assert_eq!(
        fixture["baselineCommit"],
        "1bbaa55822025dfc96e683785d93f5ba224d95d3"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for case in cases {
        let common = &case["common"];
        let context = GatewayServiceContext::new(
            case["service"].as_str().unwrap(),
            common["displayName"].as_str().unwrap(),
            common["upstreamBaseUrl"].as_str().unwrap(),
        )
        .with_broker_hosts(
            serde_json::from_value::<Vec<String>>(common["brokerHosts"].clone()).unwrap(),
        )
        .with_credential_modes(
            serde_json::from_value::<Vec<String>>(common["credentialModes"].clone()).unwrap(),
        )
        .with_auth_modes(
            serde_json::from_value::<Vec<String>>(common["authModes"].clone()).unwrap(),
        );
        let public: toml::Value = toml::from_str(case["gatewayToml"].as_str().unwrap()).unwrap();
        let module = GIT_HTTP_GATEWAY
            .parse_config(toml::Value::Table(
                [("git".to_string(), public["git"].clone())]
                    .into_iter()
                    .collect(),
            ))
            .unwrap();
        let mut errors = Vec::new();
        module.validate(&context, &mut errors);
        assert!(errors.is_empty(), "{}: {errors:?}", case["name"]);
        let descriptor = module.descriptor(&context);
        descriptor.validate().unwrap();
        assert_eq!(
            descriptor_projection(&descriptor),
            case["descriptor"],
            "{}",
            case["name"]
        );
        // This added metadata explicitly distinguishes a read-only verification
        // probe from setup for a push-only service; baseline policy is unchanged.
        assert_eq!(
            descriptor.credentials.verification_supported,
            case["verificationSupported"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}
