//! Resource types, their canonical target grammars, and policy selectors.
use serde::{Deserialize, Deserializer, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;

/// Registered resource type identifier, such as `git_repository`. The
/// identifier alone carries no semantics: a [`ResourceTypeRegistry`] resolves
/// it to the descriptor that defines its canonical grammar and selectors.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceType(Cow<'static, str>);

impl ResourceType {
    pub const fn from_static(id: &'static str) -> Self {
        Self(Cow::Borrowed(id))
    }

    pub fn new(id: impl Into<String>) -> Result<Self, String> {
        let id = id.into();
        if is_resource_type_id(&id) {
            Ok(Self(Cow::Owned(id)))
        } else {
            Err(format!(
                "resource type {id} must match ^[a-z][a-z0-9_]{{0,63}}$"
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ResourceType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ResourceType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

pub fn is_resource_type_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Defines a resource type: its canonical target grammar, the selector forms
/// it supports, and the labels clients show. Backends declare these as
/// statics and a [`ResourceTypeRegistry`] makes them resolvable.
#[derive(Debug)]
pub struct ResourceTypeDescriptor {
    pub id: ResourceType,
    pub label: &'static str,
    pub plural_label: &'static str,
    /// Example canonical target for forms and help text.
    pub example: &'static str,
    /// Canonical target grammar. Exact selectors and every resolved target
    /// of this type must satisfy it, which keeps namespace prefix matching
    /// sound.
    pub canonical: fn(&str) -> bool,
    pub namespace: Option<NamespaceSelectorDescriptor>,
    /// Private string attributes on exact, managed resources.
    pub attributes: &'static [ResourceAttributeDescriptor],
    /// Maps a selector of this type to the action inputs that address it,
    /// such as a CloudBees CI job's `controller` and `job`. Discovery shows
    /// these next to resource values so callers need not parse them.
    pub action_inputs: Option<ResourceActionInputs>,
}

/// Projects a selector onto the action inputs that address it.
pub type ResourceActionInputs =
    fn(&ResourceSelector) -> Option<serde_json::Map<String, serde_json::Value>>;

/// A private string field owned and validated by a resource type.
#[derive(Debug)]
pub struct ResourceAttributeDescriptor {
    pub name: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub required: bool,
    /// Must not expose the supplied value in diagnostics.
    pub validate: fn(&str) -> bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceAttributeMetadata {
    pub name: String,
    pub label: String,
    pub description: String,
    pub required: bool,
    pub secret: bool,
}

/// Private values are deliberately not serializable and never appear in Debug.
#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ResourceAttributes(BTreeMap<String, String>);

impl std::fmt::Debug for ResourceAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceAttributes")
            .field("configured_count", &self.0.len())
            .finish()
    }
}

impl From<BTreeMap<String, String>> for ResourceAttributes {
    fn from(values: BTreeMap<String, String>) -> Self {
        Self(values)
    }
}

impl ResourceAttributes {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Namespace selector support: a prefix that covers every canonical target
/// below it (`value/...`).
#[derive(Debug)]
pub struct NamespaceSelectorDescriptor {
    pub valid: fn(&str) -> bool,
    /// Coverage choice label, such as "Repositories under a namespace".
    pub label: &'static str,
    /// Noun for summaries, such as "Repositories" in "Repositories under x".
    pub members_label: &'static str,
    pub example: &'static str,
}

impl ResourceTypeDescriptor {
    pub fn validate_attributes(
        &self,
        selector: &ResourceSelector,
        values: &ResourceAttributes,
        require_all: bool,
    ) -> Result<(), String> {
        if !matches!(selector, ResourceSelector::Exact { .. }) {
            return if values.is_empty() {
                Ok(())
            } else {
                Err("private attributes require an exact resource".into())
            };
        }
        for (name, value) in values.iter() {
            let Some(field) = self.attributes.iter().find(|field| field.name == name) else {
                return Err("unknown resource attribute".into());
            };
            if value.is_empty() || value.len() > 8192 || !(field.validate)(value) {
                return Err(format!("resource attribute {} is invalid", field.name));
            }
        }
        if require_all
            && self
                .attributes
                .iter()
                .any(|field| field.required && values.get(field.name).is_none())
        {
            return Err("required resource attributes are missing".into());
        }
        Ok(())
    }

    pub fn is_canonical_target(&self, value: &str) -> bool {
        (self.canonical)(value)
    }

    pub fn selector_kinds(&self) -> Vec<&'static str> {
        let mut kinds = vec!["exact"];
        if self.namespace.is_some() {
            kinds.push("namespace");
        }
        kinds.push("all");
        kinds
    }

    pub fn accepts(&self, selector: &ResourceSelector) -> bool {
        match selector {
            ResourceSelector::All => true,
            ResourceSelector::Exact { value } => self.is_canonical_target(value),
            ResourceSelector::Namespace { value } => self
                .namespace
                .as_ref()
                .is_some_and(|namespace| (namespace.valid)(value)),
        }
    }

    pub fn metadata(&self) -> ResourceTypeMetadata {
        ResourceTypeMetadata {
            id: self.id.clone(),
            attributes: self
                .attributes
                .iter()
                .map(|field| ResourceAttributeMetadata {
                    name: field.name.into(),
                    label: field.label.into(),
                    description: field.description.into(),
                    required: field.required,
                    secret: true,
                })
                .collect(),
            label: self.label.to_string(),
            plural_label: self.plural_label.to_string(),
            example: self.example.to_string(),
            selectors: self
                .selector_kinds()
                .into_iter()
                .map(str::to_string)
                .collect(),
            namespace: self
                .namespace
                .as_ref()
                .map(|namespace| NamespaceSelectorMetadata {
                    label: namespace.label.to_string(),
                    members_label: namespace.members_label.to_string(),
                    example: namespace.example.to_string(),
                }),
        }
    }
}

/// Client-facing description of a registered resource type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTypeMetadata {
    pub id: ResourceType,
    pub label: String,
    pub plural_label: String,
    pub example: String,
    pub selectors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<ResourceAttributeMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<NamespaceSelectorMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceSelectorMetadata {
    pub label: String,
    pub members_label: String,
    pub example: String,
}

/// The resource types this build understands. A type is never inferred from
/// a service or scope name; every stored or configured resource must name a
/// registered type. Listings keep registration order, so clients can treat
/// the first type as the default.
#[derive(Debug, Clone)]
pub struct ResourceTypeRegistry {
    types: BTreeMap<ResourceType, &'static ResourceTypeDescriptor>,
    order: Vec<&'static ResourceTypeDescriptor>,
}

impl ResourceTypeRegistry {
    pub fn new(
        descriptors: impl IntoIterator<Item = &'static ResourceTypeDescriptor>,
    ) -> Result<Self, Vec<String>> {
        let mut types = BTreeMap::new();
        let mut order = Vec::new();
        let mut errors = Vec::new();
        for descriptor in descriptors {
            if !is_resource_type_id(descriptor.id.as_str()) {
                errors.push(format!(
                    "resource type {} has an invalid identifier",
                    descriptor.id
                ));
            }
            if !(descriptor.canonical)(descriptor.example) {
                errors.push(format!(
                    "resource type {} example is not a canonical target",
                    descriptor.id
                ));
            }
            if let Some(namespace) = &descriptor.namespace
                && !(namespace.valid)(namespace.example)
            {
                errors.push(format!(
                    "resource type {} namespace example is not a valid namespace",
                    descriptor.id
                ));
            }
            let mut attribute_names = std::collections::BTreeSet::new();
            for attribute in descriptor.attributes {
                if attribute.name.is_empty()
                    || attribute.name.len() > 64
                    || !attribute
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    || !attribute_names.insert(attribute.name)
                {
                    errors.push(format!(
                        "resource type {} has invalid or duplicate attribute names",
                        descriptor.id
                    ));
                }
            }
            if types.insert(descriptor.id.clone(), descriptor).is_some() {
                errors.push(format!(
                    "resource type {} is registered more than once",
                    descriptor.id
                ));
            } else {
                order.push(descriptor);
            }
        }
        if errors.is_empty() {
            Ok(Self { types, order })
        } else {
            Err(errors)
        }
    }

    pub fn get(&self, id: &ResourceType) -> Option<&'static ResourceTypeDescriptor> {
        self.types.get(id).copied()
    }

    pub fn descriptors(&self) -> impl Iterator<Item = &'static ResourceTypeDescriptor> + '_ {
        self.order.iter().copied()
    }

    pub fn ids(&self) -> impl Iterator<Item = &ResourceType> + '_ {
        self.order.iter().map(|descriptor| &descriptor.id)
    }

    pub fn metadata(&self) -> Vec<ResourceTypeMetadata> {
        self.descriptors()
            .map(ResourceTypeDescriptor::metadata)
            .collect()
    }

    /// Type-specific checks for one resource: its type is registered and its
    /// selector form and value are valid for that type.
    pub fn validate_selector(
        &self,
        resource_id: &str,
        resource_type: &ResourceType,
        selector: &ResourceSelector,
    ) -> Result<(), String> {
        let Some(descriptor) = self.get(resource_type) else {
            return Err(format!(
                "resource {resource_id} uses unregistered resource type {resource_type}"
            ));
        };
        if descriptor.accepts(selector) {
            Ok(())
        } else {
            Err(format!(
                "resource {resource_id} selector is invalid for {resource_type}"
            ))
        }
    }
}

/// Git repositories are shared by GitLab REST and Git HTTP gateways: one
/// resource entry authorizes both. Canonical paths have at least two segments
/// and are not all digits, so they cannot be confused with numeric project IDs.
pub static GIT_REPOSITORY_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor {
    action_inputs: None,
    attributes: &[],
    id: ResourceType::from_static("git_repository"),
    label: "Git repository",
    plural_label: "Git repositories",
    example: "engineering/payments",
    canonical: is_canonical_repository_path,
    namespace: Some(NamespaceSelectorDescriptor {
        valid: is_repository_selector_path,
        label: "Repositories under a namespace",
        members_label: "Repositories",
        example: "engineering/platform",
    }),
};

pub fn is_canonical_repository_path(value: &str) -> bool {
    is_repository_selector_path(value)
        && value.split('/').count() >= 2
        && !value.bytes().all(|byte| byte.is_ascii_digit())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceSelector {
    Exact { value: String },
    Namespace { value: String },
    All,
}

impl<'de> Deserialize<'de> for ResourceSelector {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Kind {
            Exact,
            Namespace,
            All,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SelectorInput {
            kind: Kind,
            #[serde(default, deserialize_with = "present_value")]
            value: Option<String>,
        }
        fn present_value<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<String>, D::Error> {
            String::deserialize(deserializer).map(Some)
        }
        let input = SelectorInput::deserialize(deserializer)?;
        match (input.kind, input.value) {
            (Kind::Exact, Some(value)) => Ok(Self::Exact { value }),
            (Kind::Namespace, Some(value)) => Ok(Self::Namespace { value }),
            (Kind::All, None) => Ok(Self::All),
            (Kind::All, Some(_)) => Err(serde::de::Error::custom(
                "all selector must not include value",
            )),
            (_, None) => Err(serde::de::Error::missing_field("value")),
        }
    }
}

impl ResourceSelector {
    pub fn matches(&self, target: &str) -> bool {
        match self {
            Self::Exact { value } => value == target,
            Self::Namespace { value } => target
                .strip_prefix(value)
                .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1),
            Self::All => true,
        }
    }
    pub fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::All, _) => true,
            (_, Self::All) => false,
            (_, Self::Exact { value }) => self.matches(value),
            (Self::Namespace { value }, Self::Namespace { value: other }) => {
                value == other || self.matches(other)
            }
            _ => false,
        }
    }
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        if self.contains(other) {
            Some(other.clone())
        } else if other.contains(self) {
            Some(self.clone())
        } else {
            None
        }
    }
}

pub fn is_repository_selector_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.ends_with('/')
        && value.split('/').all(is_repository_selector_segment)
        && !value.contains("//")
}

pub fn is_repository_selector_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.contains('*')
        && !segment.contains('%')
        && !segment.contains('\\')
        && !segment
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '?' | '#' | ':'))
}
