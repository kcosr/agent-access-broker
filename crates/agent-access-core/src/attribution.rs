use crate::{
    ProviderAttributionConfig, ServiceDescriptor, matching_attribution_capabilities,
    validate_attribution_pattern,
};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionConfig {
    /// Action glob patterns, keyed by service, that enable attribution
    /// footers on the service's attribution-capable actions.
    #[serde(default)]
    pub actions: BTreeMap<String, Vec<String>>,
}

impl AttributionConfig {
    /// Active attribution for a service: its descriptor's capabilities
    /// selected by `attribution.actions.<service>`.
    pub fn for_service(&self, descriptor: &ServiceDescriptor) -> ProviderAttributionConfig {
        let patterns = self
            .actions
            .get(&descriptor.service)
            .map(Vec::as_slice)
            .unwrap_or_default();
        ProviderAttributionConfig::from_patterns(descriptor, patterns)
    }
}

pub(crate) fn validate_attribution_config(
    attribution: &AttributionConfig,
    descriptors: &BTreeMap<String, std::sync::Arc<ServiceDescriptor>>,
    errors: &mut Vec<String>,
) {
    for (service, patterns) in &attribution.actions {
        let Some(descriptor) = descriptors.get(service) else {
            errors.push(format!(
                "attribution.actions.{service} names a service that is not configured"
            ));
            continue;
        };
        if !descriptor
            .actions
            .iter()
            .any(|action| action.attribution.is_some())
        {
            errors.push(format!(
                "attribution.actions.{service} names a service without attribution-capable actions"
            ));
            continue;
        }
        for (index, pattern) in patterns.iter().enumerate() {
            let field = format!("attribution.actions.{service}[{index}]");
            if let Err(error) = validate_attribution_pattern(pattern) {
                errors.push(format!("{field} {error}"));
                continue;
            }
            if matching_attribution_capabilities(descriptor, pattern)
                .next()
                .is_none()
            {
                errors.push(format!(
                    "{field} must match at least one attribution-capable {service} action enabled by the current configuration"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttributionCapability, AttributionRepresentation, AttributionVerb};
    use serde_json::json;

    fn descriptor(actions: &[(&str, Option<AttributionCapability>)]) -> ServiceDescriptor {
        ServiceDescriptor {
            service: "example".to_string(),
            display_name: "Example".to_string(),
            surface: crate::ServiceSurface::Invoke,
            resource_scopes: BTreeMap::new(),
            actions: actions
                .iter()
                .map(|(action, capability)| {
                    let descriptor = crate::ActionDescriptor::new(*action, "test", json!({}))
                        .credential_modes(["service"]);
                    match capability {
                        Some(capability) => descriptor.attribution(*capability),
                        None => descriptor,
                    }
                })
                .collect(),
            credentials: Default::default(),
            presentation_body_limit: None,
        }
    }

    const BODY_ADD: AttributionCapability = AttributionCapability::required(
        AttributionVerb::Add,
        "body",
        AttributionRepresentation::GitlabMarkdown,
    );
    const DESCRIPTION_UPDATE: AttributionCapability = AttributionCapability::optional(
        AttributionVerb::Update,
        "description",
        AttributionRepresentation::Adf,
    );

    fn example_descriptor() -> ServiceDescriptor {
        descriptor(&[
            ("issue.create", Some(BODY_ADD)),
            ("issue.update", Some(DESCRIPTION_UPDATE)),
            ("issue.note.add", Some(BODY_ADD)),
            ("issue.view", None),
            ("merge_request.create", Some(BODY_ADD)),
        ])
    }

    #[test]
    fn provider_attribution_config_resolves_globs_against_capabilities_only() {
        let config = ProviderAttributionConfig::from_patterns(
            &example_descriptor(),
            &["issue.*".to_string()],
        );

        assert_eq!(config.capability("issue.create"), Some(BODY_ADD));
        assert_eq!(config.capability("issue.update"), Some(DESCRIPTION_UPDATE));
        assert!(config.capability("issue.note.add").is_some());
        assert!(config.capability("merge_request.create").is_none());
        assert!(config.capability("issue.view").is_none());
    }

    #[test]
    fn star_pattern_expands_only_declared_attribution_capabilities() {
        let config =
            ProviderAttributionConfig::from_patterns(&example_descriptor(), &["*".to_string()]);

        assert!(config.capability("issue.create").is_some());
        assert!(config.capability("merge_request.create").is_some());
        assert!(config.capability("issue.view").is_none());
    }

    #[test]
    fn attribution_config_validation_rejects_unknown_services_and_unmatched_patterns() {
        let attribution = AttributionConfig {
            actions: BTreeMap::from([
                (
                    "example".to_string(),
                    vec![
                        "issue.*".to_string(),
                        "missing.*".to_string(),
                        "bad pattern".to_string(),
                    ],
                ),
                ("view_only".to_string(), vec!["*".to_string()]),
                ("unconfigured".to_string(), vec!["*".to_string()]),
            ]),
        };
        let descriptors = BTreeMap::from([
            (
                "example".to_string(),
                std::sync::Arc::new(example_descriptor()),
            ),
            (
                "view_only".to_string(),
                std::sync::Arc::new(ServiceDescriptor {
                    service: "view_only".to_string(),
                    ..descriptor(&[("item.view", None)])
                }),
            ),
        ]);
        let mut errors = Vec::new();

        validate_attribution_config(&attribution, &descriptors, &mut errors);

        assert_eq!(
            errors,
            vec![
                "attribution.actions.example[1] must match at least one attribution-capable example action enabled by the current configuration",
                "attribution.actions.example[2] contains unsupported glob characters",
                "attribution.actions.unconfigured names a service that is not configured",
                "attribution.actions.view_only names a service without attribution-capable actions",
            ]
        );
    }
}
