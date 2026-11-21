//! Pure, type-owned location entry and authored-coordinate projection.
use crate::{ResourceSelector, ResourceType, ResourceTypeRegistry};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// An authored container coordinate, such as a canonical space key. It is not
/// evidence that a content object exists in that container.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceContainer {
    pub resource_type: ResourceType,
    pub value: String,
}

impl ResourceContainer {
    pub fn new(resource_type: ResourceType, value: impl Into<String>) -> Self {
        Self {
            resource_type,
            value: value.into(),
        }
    }
}

/// Coordinates a resource type extracts from its canonical locator. The host
/// consumes these fields without parsing a provider-specific URL.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSelectorProjection {
    pub site_origin: String,
    pub root_kind: String,
    pub containers: Vec<ResourceContainer>,
}

impl ResourceSelectorProjection {
    pub fn new(
        site_origin: impl Into<String>,
        root_kind: impl Into<String>,
        containers: Vec<ResourceContainer>,
    ) -> Self {
        Self {
            site_origin: site_origin.into(),
            root_kind: root_kind.into(),
            containers,
        }
    }

    pub(crate) fn validate(
        &self,
        registry: &ResourceTypeRegistry,
    ) -> Result<(), LocationNormalizationError> {
        if !is_canonical_https_dns_origin(&self.site_origin)
            || !is_kind(&self.root_kind)
            || self.containers.is_empty()
            || self.containers.len() > 8
        {
            return Err(LocationNormalizationError::new(
                "selector",
                "invalid authored location coordinates",
            ));
        }
        let mut types = BTreeSet::new();
        for container in &self.containers {
            if !types.insert(&container.resource_type)
                || registry
                    .get(&container.resource_type)
                    .is_none_or(|descriptor| !descriptor.is_canonical_target(&container.value))
            {
                return Err(LocationNormalizationError::new(
                    "selector",
                    "invalid authored container coordinates",
                ));
            }
        }
        Ok(())
    }
}

/// A pure projection hook. It must not perform upstream work or infer ancestry.
pub type ResourceSelectorProjector =
    fn(&ResourceSelector) -> Result<ResourceSelectorProjection, LocationNormalizationError>;

/// A pure lexical normalizer, registered by a native resource type.
pub type LocationNormalizer =
    for<'a> fn(
        &LocationNormalizationRequest<'a>,
    ) -> Result<NormalizedResourceLocation, LocationNormalizationError>;

/// Local input to a registered normalizer. The declared site is supplied by the
/// host from the admitted service descriptor, not selected from the pasted URL.
#[derive(Debug, Clone, Copy)]
pub struct LocationNormalizationRequest<'a> {
    declared_site: &'a str,
    url: &'a str,
    coverage: &'a str,
    space_key: Option<&'a str>,
}

impl<'a> LocationNormalizationRequest<'a> {
    pub fn new(declared_site: &'a str, url: &'a str, coverage: &'a str) -> Self {
        Self {
            declared_site,
            url,
            coverage,
            space_key: None,
        }
    }
    pub fn with_space_key(mut self, space_key: Option<&'a str>) -> Self {
        self.space_key = space_key;
        self
    }
    pub fn declared_site(&self) -> &'a str {
        self.declared_site
    }
    pub fn url(&self) -> &'a str {
        self.url
    }
    pub fn coverage(&self) -> &'a str {
        self.coverage
    }
    pub fn space_key(&self) -> Option<&'a str> {
        self.space_key
    }
}

/// A lexical preview. `verification` deliberately never claims upstream validation.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedResourceLocation {
    pub resource_type: ResourceType,
    pub selector: ResourceSelector,
    pub location_kind: String,
    pub configured_space_key: String,
    pub verification: &'static str,
}

impl NormalizedResourceLocation {
    pub fn new(
        resource_type: ResourceType,
        selector: ResourceSelector,
        location_kind: impl Into<String>,
        configured_space_key: impl Into<String>,
    ) -> Self {
        Self {
            resource_type,
            selector,
            location_kind: location_kind.into(),
            configured_space_key: configured_space_key.into(),
            verification: "not_checked",
        }
    }
}

/// A value-free, field-specific lexical failure. Both fields are static text,
/// preventing caller URL contents from being included by interpolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct LocationNormalizationError {
    field: &'static str,
    message: &'static str,
}

impl LocationNormalizationError {
    pub const fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }
    pub const fn field(&self) -> &'static str {
        self.field
    }
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

/// A configured service's offline URL-entry capability. The normalizer is a
/// registered resource type; its output may be another declared resource type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationEntryCapability {
    normalizer: ResourceType,
    resource_types: Vec<ResourceType>,
    location_kinds: Vec<String>,
    coverage_kinds: Vec<String>,
}

impl LocationEntryCapability {
    pub fn new(
        normalizer: ResourceType,
        resource_types: Vec<ResourceType>,
        location_kinds: Vec<String>,
        coverage_kinds: Vec<String>,
    ) -> Self {
        Self {
            normalizer,
            resource_types,
            location_kinds,
            coverage_kinds,
        }
    }
    pub fn normalizer(&self) -> &ResourceType {
        &self.normalizer
    }
    pub fn resource_types(&self) -> &[ResourceType] {
        &self.resource_types
    }
    pub fn location_kinds(&self) -> &[String] {
        &self.location_kinds
    }
    pub fn coverage_kinds(&self) -> &[String] {
        &self.coverage_kinds
    }

    pub(crate) fn validate(&self) -> bool {
        !self.resource_types.is_empty()
            && self.resource_types.len() <= 16
            && self.resource_types.iter().collect::<BTreeSet<_>>().len()
                == self.resource_types.len()
            && !self.location_kinds.is_empty()
            && self.location_kinds.len() <= 16
            && self.location_kinds.iter().all(|kind| is_kind(kind))
            && self.location_kinds.iter().collect::<BTreeSet<_>>().len()
                == self.location_kinds.len()
            && !self.coverage_kinds.is_empty()
            && self.coverage_kinds.len() <= 8
            && self
                .coverage_kinds
                .iter()
                .all(|kind| matches!(kind.as_str(), "space" | "exact" | "subtree"))
            && self.coverage_kinds.iter().collect::<BTreeSet<_>>().len()
                == self.coverage_kinds.len()
    }
}

impl ResourceTypeRegistry {
    /// Dispatches a pure normalizer and validates its output through the same
    /// canonical selector contract that direct API, configuration and reload use.
    pub fn normalize_location(
        &self,
        normalizer: &ResourceType,
        request: &LocationNormalizationRequest<'_>,
    ) -> Result<NormalizedResourceLocation, LocationNormalizationError> {
        if !is_canonical_https_dns_origin(request.declared_site) {
            return Err(LocationNormalizationError::new(
                "service",
                "service location origin is invalid",
            ));
        }
        let descriptor = self.get(normalizer).ok_or_else(|| {
            LocationNormalizationError::new("service", "location normalizer is unregistered")
        })?;
        let normalized = descriptor.normalize_location(request)?;
        let output_type = self.get(&normalized.resource_type).ok_or_else(|| {
            LocationNormalizationError::new(
                "selector",
                "normalizer returned an unregistered resource type",
            )
        })?;
        if !output_type.accepts(&normalized.selector)
            || normalized.verification != "not_checked"
            || !is_kind(&normalized.location_kind)
            || normalized.configured_space_key.is_empty()
            || normalized.configured_space_key.len() > 8192
        {
            return Err(LocationNormalizationError::new(
                "selector",
                "normalizer returned invalid canonical metadata",
            ));
        }
        if let Some(projection) = output_type.project_selector(&normalized.selector)? {
            projection.validate(self)?;
            if projection.site_origin != request.declared_site {
                return Err(LocationNormalizationError::new(
                    "url",
                    "location does not match the configured site",
                ));
            }
        }
        Ok(normalized)
    }
}

pub(crate) fn is_kind(kind: &str) -> bool {
    let bytes = kind.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

pub(crate) fn is_canonical_https_dns_origin(origin: &str) -> bool {
    let Ok(url) = url::Url::parse(origin) else {
        return false;
    };
    url.scheme() == "https"
        && matches!(url.host(), Some(url::Host::Domain(_)))
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.origin().ascii_serialization() == origin
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ResourceTypeDescriptor, ServiceDescriptor, UpstreamAuthority};

    fn key(value: &str) -> bool {
        value == "ENG"
    }
    fn normalize(
        request: &LocationNormalizationRequest<'_>,
    ) -> Result<NormalizedResourceLocation, LocationNormalizationError> {
        if request.url() != "https://docs.example.test/ENG"
            || request.coverage() != "space"
            || request.space_key().is_some_and(|key| key != "ENG")
        {
            return Err(LocationNormalizationError::new(
                "url",
                "unsupported location shape",
            ));
        }
        Ok(NormalizedResourceLocation::new(
            ResourceType::from_static("normalizer_area"),
            ResourceSelector::Exact {
                value: "ENG".into(),
            },
            "space",
            "ENG",
        ))
    }
    fn invalid_output(
        _: &LocationNormalizationRequest<'_>,
    ) -> Result<NormalizedResourceLocation, LocationNormalizationError> {
        Ok(NormalizedResourceLocation::new(
            ResourceType::from_static("normalizer_area"),
            ResourceSelector::Subtree {
                value: "ENG".into(),
            },
            "space",
            "ENG",
        ))
    }
    static AREA: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
        ResourceType::from_static("normalizer_area"),
        "Area",
        "Areas",
        "ENG",
        key,
        &[],
    )
    .with_location_normalizer(normalize);

    fn capability() -> LocationEntryCapability {
        LocationEntryCapability::new(
            ResourceType::from_static("normalizer_area"),
            vec![ResourceType::from_static("normalizer_area")],
            vec!["space".into()],
            vec!["space".into()],
        )
    }

    #[test]
    fn normalizer_dispatch_is_pure_and_output_is_canonical_not_verified() {
        let registry = ResourceTypeRegistry::new([&AREA]).unwrap();
        let request = LocationNormalizationRequest::new(
            "https://docs.example.test",
            "https://docs.example.test/ENG",
            "space",
        )
        .with_space_key(Some("ENG"));
        let result = registry
            .normalize_location(&ResourceType::from_static("normalizer_area"), &request)
            .unwrap();
        assert_eq!(
            serde_json::to_value(result).unwrap(),
            serde_json::json!({"resourceType":"normalizer_area","selector":{"kind":"exact","value":"ENG"},"locationKind":"space","configuredSpaceKey":"ENG","verification":"not_checked"})
        );
        let invalid = LocationNormalizationRequest::new(
            "https://docs.example.test",
            "https://private.example.test/sensitive-title",
            "space",
        );
        let error = registry
            .normalize_location(&ResourceType::from_static("normalizer_area"), &invalid)
            .unwrap_err();
        assert_eq!(error.field(), "url");
        assert_eq!(error.to_string(), "unsupported location shape");
        assert!(!format!("{error:?}").contains("private"));
    }

    #[test]
    fn normalizer_output_cannot_bypass_registered_selector_grammar() {
        let descriptor = AREA.clone().with_location_normalizer(invalid_output);
        let registry =
            ResourceTypeRegistry::from_shared([std::sync::Arc::new(descriptor)]).unwrap();
        let request = LocationNormalizationRequest::new(
            "https://docs.example.test",
            "https://docs.example.test/ENG",
            "space",
        );
        assert!(
            registry
                .normalize_location(&ResourceType::from_static("normalizer_area"), &request)
                .is_err()
        );
        assert!(
            registry
                .normalize_location(&ResourceType::from_static("absent"), &request)
                .is_err()
        );
    }

    #[test]
    fn location_capability_requires_https_dns_root_origin_and_registered_hook() {
        let registry = ResourceTypeRegistry::new([&AREA]).unwrap();
        let valid = ServiceDescriptor::new("docs", "Docs")
            .with_location_entry(capability())
            .with_upstream_authority(
                UpstreamAuthority::from_base_url("https://docs.example.test").unwrap(),
            );
        assert!(valid.validate().is_ok());
        assert!(valid.validate_resource_types(&registry).is_empty());
        for base in [
            "http://docs.example.test",
            "https://127.0.0.1",
            "https://docs.example.test:8443",
            "https://docs.example.test/nested",
        ] {
            let invalid = ServiceDescriptor::new("docs", "Docs")
                .with_location_entry(capability())
                .with_upstream_authority(UpstreamAuthority::from_base_url(base).unwrap());
            assert!(invalid.validate().is_err(), "{base}");
        }
        assert!(
            ServiceDescriptor::new("docs", "Docs")
                .with_location_entry(capability())
                .validate()
                .is_err()
        );
        let unavailable =
            ResourceTypeRegistry::from_shared([std::sync::Arc::new(ResourceTypeDescriptor::new(
                ResourceType::from_static("normalizer_area"),
                "Area",
                "Areas",
                "ENG",
                key,
                &[],
            ))])
            .unwrap();
        assert!(!valid.validate_resource_types(&unavailable).is_empty());
    }
}
