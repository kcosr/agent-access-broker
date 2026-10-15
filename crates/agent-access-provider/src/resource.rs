//! Resource types, their canonical target grammars, and policy selectors.
use serde::{Deserialize, Deserializer, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

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

fn is_resource_type_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// The longest value a [`ResourcePattern`] may admit, which is also the
/// longest private attribute value.
const MAX_PATTERN_VALUE_BYTES: usize = 8 * 1024;
/// The longest pattern source.
const MAX_PATTERN_SOURCE_BYTES: usize = 8 * 1024;
/// The compiled program and lazy DFA budgets of one pattern.
const MAX_COMPILED_PATTERN_BYTES: usize = 256 * 1024;

/// A declared value grammar: a regular expression that must match the whole
/// value, and a maximum value length in bytes.
///
/// Patterns use the syntax of the [`regex`](https://docs.rs/regex) crate,
/// whose matching time is linear in the value length; lookaround and
/// backreferences are unsupported. The pattern is anchored at both ends, so
/// `[A-Z]{2,10}` accepts `OPS` but not `OPS-1`. The source is at most 8 KiB,
/// the length bound is 1 to 8,192 bytes, and the compiled pattern must fit
/// 256 KiB program and lazy DFA budgets.
///
/// ```
/// use agent_access_provider::ResourcePattern;
///
/// let pattern = ResourcePattern::new("[A-Z][A-Z0-9]{1,9}", 10).unwrap();
/// assert!(pattern.is_match("OPS"));
/// assert!(!pattern.is_match("OPS-1"));
/// assert!(!pattern.is_match("ABCDEFGHIJK"));
/// assert!(ResourcePattern::new("(unclosed", 10).is_err());
/// ```
#[derive(Clone)]
pub struct ResourcePattern {
    source: Arc<str>,
    max_length: usize,
    regex: regex::Regex,
}

impl ResourcePattern {
    /// Compiles `source`, matched against whole values of at most
    /// `max_length` bytes.
    pub fn new(source: impl Into<String>, max_length: usize) -> Result<Self, String> {
        let source = source.into();
        if source.is_empty() {
            return Err("resource pattern must not be empty".into());
        }
        if source.len() > MAX_PATTERN_SOURCE_BYTES {
            return Err(format!(
                "resource pattern exceeds {MAX_PATTERN_SOURCE_BYTES} bytes"
            ));
        }
        if max_length == 0 || max_length > MAX_PATTERN_VALUE_BYTES {
            return Err(format!(
                "resource pattern maximum length must be 1 to {MAX_PATTERN_VALUE_BYTES} bytes"
            ));
        }
        let regex = regex::RegexBuilder::new(&format!(r"\A(?:{source})\z"))
            .size_limit(MAX_COMPILED_PATTERN_BYTES)
            .dfa_size_limit(MAX_COMPILED_PATTERN_BYTES)
            .build()
            .map_err(|error| match error {
                regex::Error::CompiledTooBig(_) => {
                    "resource pattern exceeds the compilation budget".to_string()
                }
                _ => "resource pattern is not a valid regular expression".to_string(),
            })?;
        Ok(Self {
            source: source.into(),
            max_length,
            regex,
        })
    }

    /// The pattern as declared, without the anchors the match adds.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The longest value, in bytes, the pattern accepts.
    pub const fn max_length(&self) -> usize {
        self.max_length
    }

    /// Whether `value` is within the length bound and the pattern matches
    /// all of it.
    pub fn is_match(&self, value: &str) -> bool {
        value.len() <= self.max_length && self.regex.is_match(value)
    }
}

/// Patterns are equal when their sources and length bounds are.
impl PartialEq for ResourcePattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.max_length == other.max_length
    }
}

impl Eq for ResourcePattern {}

impl std::fmt::Debug for ResourcePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourcePattern")
            .field("source", &self.source)
            .field("max_length", &self.max_length)
            .finish()
    }
}

/// How a type or attribute decides which values are valid.
#[derive(Debug, Clone)]
enum ValueGrammar {
    /// A static grammar function.
    Function(fn(&str) -> bool),
    /// A declared pattern.
    Pattern(ResourcePattern),
    /// Any value: a declared attribute without a pattern.
    Unconstrained,
}

impl ValueGrammar {
    fn accepts(&self, value: &str) -> bool {
        match self {
            Self::Function(valid) => valid(value),
            Self::Pattern(pattern) => pattern.is_match(value),
            Self::Unconstrained => true,
        }
    }

    fn pattern(&self) -> Option<&ResourcePattern> {
        match self {
            Self::Pattern(pattern) => Some(pattern),
            Self::Function(_) | Self::Unconstrained => None,
        }
    }
}

#[allow(clippy::ptr_arg)] // `Deref` is not callable in a `const fn`, so this matches the `Cow`.
const fn cow_str<'a>(value: &'a Cow<'static, str>) -> &'a str {
    match value {
        Cow::Borrowed(value) => value,
        Cow::Owned(value) => value.as_str(),
    }
}

/// Defines a resource type: its canonical target grammar, the selector forms
/// it supports, and the labels clients show. Backends declare these as
/// statics with the `const` builder and a [`ResourceTypeRegistry`] makes
/// them resolvable. A type declared at runtime, such as one an imported
/// service describes, is built with [`ResourceTypeDescriptor::declared`] from
/// owned labels, a [`ResourcePattern`] and declared attributes.
///
/// ```
/// use agent_access_provider::{
///     NamespaceSelectorDescriptor, ResourceType, ResourceTypeDescriptor,
/// };
///
/// fn is_shelf(value: &str) -> bool {
///     !value.is_empty() && !value.contains('/')
/// }
/// fn is_item(value: &str) -> bool {
///     value.split_once('/').is_some_and(|(shelf, item)| is_shelf(shelf) && is_shelf(item))
/// }
///
/// pub static ITEM_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
///     ResourceType::from_static("example_item"),
///     "Item",
///     "Items",
///     "shelf/item",
///     is_item,
/// )
/// .with_namespace(NamespaceSelectorDescriptor::new(
///     is_shelf,
///     "Items on a shelf",
///     "Items",
///     "shelf",
/// ));
/// assert_eq!(ITEM_RESOURCE.id().as_str(), "example_item");
/// assert!(ITEM_RESOURCE.is_canonical_target("shelf/item"));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ResourceTypeDescriptor {
    id: ResourceType,
    label: Cow<'static, str>,
    plural_label: Cow<'static, str>,
    example: Cow<'static, str>,
    canonical: ValueGrammar,
    namespace: Option<NamespaceSelectorDescriptor>,
    attributes: Cow<'static, [ResourceAttributeDescriptor]>,
    action_inputs: Option<ResourceActionInputs>,
}

/// Projects a selector onto the action inputs that address it.
pub type ResourceActionInputs =
    fn(&ResourceSelector) -> Option<serde_json::Map<String, serde_json::Value>>;

/// A private string field owned and validated by a resource type: declared
/// in a static descriptor's `const` attribute list, or with
/// [`ResourceAttributeDescriptor::declared`] for a declared type.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ResourceAttributeDescriptor {
    name: Cow<'static, str>,
    label: Cow<'static, str>,
    description: Cow<'static, str>,
    required: bool,
    validate: ValueGrammar,
}

impl ResourceAttributeDescriptor {
    /// An attribute every exact resource of the type must carry. `validate`
    /// must not expose the supplied value in diagnostics.
    pub const fn required(
        name: &'static str,
        label: &'static str,
        description: &'static str,
        validate: fn(&str) -> bool,
    ) -> Self {
        Self {
            name: Cow::Borrowed(name),
            label: Cow::Borrowed(label),
            description: Cow::Borrowed(description),
            required: true,
            validate: ValueGrammar::Function(validate),
        }
    }

    /// An attribute an exact resource of the type may carry. `validate`
    /// must not expose the supplied value in diagnostics.
    pub const fn optional(
        name: &'static str,
        label: &'static str,
        description: &'static str,
        validate: fn(&str) -> bool,
    ) -> Self {
        Self {
            name: Cow::Borrowed(name),
            label: Cow::Borrowed(label),
            description: Cow::Borrowed(description),
            required: false,
            validate: ValueGrammar::Function(validate),
        }
    }

    /// An attribute of a declared type. Values must match `pattern` when one
    /// is given; without one, any value within the attribute bounds is
    /// valid.
    pub fn declared(
        name: impl Into<String>,
        label: impl Into<String>,
        description: impl Into<String>,
        required: bool,
        pattern: Option<ResourcePattern>,
    ) -> Self {
        Self {
            name: Cow::Owned(name.into()),
            label: Cow::Owned(label.into()),
            description: Cow::Owned(description.into()),
            required,
            validate: pattern.map_or(ValueGrammar::Unconstrained, ValueGrammar::Pattern),
        }
    }

    pub const fn name(&self) -> &str {
        cow_str(&self.name)
    }

    pub const fn label(&self) -> &str {
        cow_str(&self.label)
    }

    pub const fn description(&self) -> &str {
        cow_str(&self.description)
    }

    pub const fn is_required(&self) -> bool {
        self.required
    }

    /// The declared pattern of a declared attribute, if it has one.
    pub fn pattern(&self) -> Option<&ResourcePattern> {
        self.validate.pattern()
    }

    /// Whether `value` passes the attribute's own validation.
    pub fn is_valid(&self, value: &str) -> bool {
        self.validate.accepts(value)
    }
}

/// A private resource attribute as clients see it.
#[non_exhaustive]
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
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct NamespaceSelectorDescriptor {
    valid: fn(&str) -> bool,
    label: &'static str,
    members_label: &'static str,
    example: &'static str,
}

impl NamespaceSelectorDescriptor {
    /// Namespace selectors whose values `valid` accepts. `label` names the
    /// coverage choice, such as "Repositories under a namespace";
    /// `members_label` is the noun for summaries, such as "Repositories" in
    /// "Repositories under x"; `example` must be a valid namespace.
    pub const fn new(
        valid: fn(&str) -> bool,
        label: &'static str,
        members_label: &'static str,
        example: &'static str,
    ) -> Self {
        Self {
            valid,
            label,
            members_label,
            example,
        }
    }

    /// Whether `value` is a valid namespace selector value.
    pub fn is_valid(&self, value: &str) -> bool {
        (self.valid)(value)
    }

    pub const fn label(&self) -> &'static str {
        self.label
    }

    pub const fn members_label(&self) -> &'static str {
        self.members_label
    }

    pub const fn example(&self) -> &'static str {
        self.example
    }
}

impl ResourceTypeDescriptor {
    /// A resource type identified by `id`, shown as `label` and
    /// `plural_label`, whose canonical targets `canonical` accepts. Exact
    /// selectors and every resolved target of the type must satisfy it,
    /// which keeps namespace prefix matching sound; `example` must be one.
    /// The type supports exact and all selectors, has no private attributes
    /// and maps selectors to no action inputs.
    pub const fn new(
        id: ResourceType,
        label: &'static str,
        plural_label: &'static str,
        example: &'static str,
        canonical: fn(&str) -> bool,
    ) -> Self {
        Self {
            id,
            label: Cow::Borrowed(label),
            plural_label: Cow::Borrowed(plural_label),
            example: Cow::Borrowed(example),
            canonical: ValueGrammar::Function(canonical),
            namespace: None,
            attributes: Cow::Borrowed(&[]),
            action_inputs: None,
        }
    }

    /// A resource type declared at runtime, such as by an imported service:
    /// identified by `id`, shown as `label` and `plural_label`, whose
    /// canonical targets are the values `pattern` matches; `example` must be
    /// one. The type supports exact and all selectors, carries `attributes`
    /// and maps selectors to no action inputs. Share it through
    /// [`ResourceTypeRegistry::from_shared`].
    ///
    /// ```
    /// use std::sync::Arc;
    /// use agent_access_provider::{
    ///     GIT_REPOSITORY_RESOURCE, ResourceAttributeDescriptor, ResourcePattern, ResourceType,
    ///     ResourceTypeDescriptor, ResourceTypeRegistry,
    /// };
    ///
    /// let project = ResourceTypeDescriptor::declared(
    ///     ResourceType::new("ticketing_project").unwrap(),
    ///     "Project",
    ///     "Projects",
    ///     "OPS",
    ///     ResourcePattern::new("[A-Z][A-Z0-9]{1,9}", 256).unwrap(),
    ///     vec![ResourceAttributeDescriptor::declared(
    ///         "region",
    ///         "Region",
    ///         "Hosting region.",
    ///         false,
    ///         Some(ResourcePattern::new("[a-z0-9-]{1,32}", 32).unwrap()),
    ///     )],
    /// );
    /// let composition = ResourceTypeRegistry::new([&GIT_REPOSITORY_RESOURCE]).unwrap();
    /// let registry = ResourceTypeRegistry::from_shared(
    ///     composition.descriptors().cloned().chain([Arc::new(project)]),
    /// )
    /// .unwrap();
    /// let project = registry.get(&ResourceType::new("ticketing_project").unwrap()).unwrap();
    /// assert!(project.is_canonical_target("OPS"));
    /// assert!(!project.is_canonical_target("ops"));
    /// assert_eq!(project.attributes()[0].name(), "region");
    /// ```
    pub fn declared(
        id: ResourceType,
        label: impl Into<String>,
        plural_label: impl Into<String>,
        example: impl Into<String>,
        pattern: ResourcePattern,
        attributes: Vec<ResourceAttributeDescriptor>,
    ) -> Self {
        Self {
            id,
            label: Cow::Owned(label.into()),
            plural_label: Cow::Owned(plural_label.into()),
            example: Cow::Owned(example.into()),
            canonical: ValueGrammar::Pattern(pattern),
            namespace: None,
            attributes: Cow::Owned(attributes),
            action_inputs: None,
        }
    }

    /// Adds namespace selectors: a prefix that covers every canonical target
    /// below it.
    pub const fn with_namespace(mut self, namespace: NamespaceSelectorDescriptor) -> Self {
        self.namespace = Some(namespace);
        self
    }

    /// Declares the private string attributes exact, managed resources of
    /// the type carry. Declare the list as its own `static`: attribute
    /// descriptors own their data, so an inline array is not promoted to a
    /// `'static` borrow. A declared type takes its attributes at
    /// construction; calling this on one panics.
    pub const fn with_attributes(
        mut self,
        attributes: &'static [ResourceAttributeDescriptor],
    ) -> Self {
        let previous = std::mem::replace(&mut self.attributes, Cow::Borrowed(attributes));
        assert!(
            matches!(previous, Cow::Borrowed(_)),
            "a declared resource type takes its attributes at construction"
        );
        // A borrowed list owns nothing, and a `const fn` cannot run the drop.
        std::mem::forget(previous);
        self
    }

    /// Maps a selector of the type to the action inputs that address it,
    /// such as a CloudBees CI job's `controller` and `job`. Discovery shows
    /// these next to resource values so callers need not parse them.
    pub const fn with_action_inputs(mut self, action_inputs: ResourceActionInputs) -> Self {
        self.action_inputs = Some(action_inputs);
        self
    }

    pub const fn id(&self) -> &ResourceType {
        &self.id
    }

    pub const fn label(&self) -> &str {
        cow_str(&self.label)
    }

    pub const fn plural_label(&self) -> &str {
        cow_str(&self.plural_label)
    }

    /// Example canonical target for forms and help text.
    pub const fn example(&self) -> &str {
        cow_str(&self.example)
    }

    pub const fn namespace(&self) -> Option<&NamespaceSelectorDescriptor> {
        self.namespace.as_ref()
    }

    /// Private string attributes on exact, managed resources.
    pub const fn attributes(&self) -> &[ResourceAttributeDescriptor] {
        match &self.attributes {
            Cow::Borrowed(attributes) => attributes,
            Cow::Owned(attributes) => attributes.as_slice(),
        }
    }

    /// The canonical-target pattern of a declared type; static types use a
    /// grammar function and have none.
    pub fn pattern(&self) -> Option<&ResourcePattern> {
        self.canonical.pattern()
    }

    /// The action inputs that address `selector`, when the type maps
    /// selectors to inputs and this one has a mapping.
    pub fn action_inputs(
        &self,
        selector: &ResourceSelector,
    ) -> Option<serde_json::Map<String, serde_json::Value>> {
        self.action_inputs
            .and_then(|action_inputs| action_inputs(selector))
    }

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
            let Some(field) = self.attributes().iter().find(|field| field.name() == name) else {
                return Err("unknown resource attribute".into());
            };
            if value.is_empty() || value.len() > MAX_PATTERN_VALUE_BYTES || !field.is_valid(value) {
                return Err(format!("resource attribute {} is invalid", field.name()));
            }
        }
        if require_all
            && self
                .attributes()
                .iter()
                .any(|field| field.required && values.get(field.name()).is_none())
        {
            return Err("required resource attributes are missing".into());
        }
        Ok(())
    }

    pub fn is_canonical_target(&self, value: &str) -> bool {
        self.canonical.accepts(value)
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
                .attributes()
                .iter()
                .map(|field| ResourceAttributeMetadata {
                    name: field.name().to_string(),
                    label: field.label().to_string(),
                    description: field.description().to_string(),
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
#[non_exhaustive]
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

/// Namespace selector support as clients see it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceSelectorMetadata {
    pub label: String,
    pub members_label: String,
    pub example: String,
}

/// The resource types a broker generation understands: the static types of
/// its build and any declared ones, each held as a shared descriptor. A type
/// is never inferred from a service or scope name; every stored or configured
/// resource must name a registered type. Listings keep registration order, so
/// clients can treat the first type as the default.
#[derive(Debug, Clone)]
pub struct ResourceTypeRegistry {
    types: BTreeMap<ResourceType, Arc<ResourceTypeDescriptor>>,
    order: Vec<Arc<ResourceTypeDescriptor>>,
}

impl ResourceTypeRegistry {
    /// A registry of a build's static descriptors.
    pub fn new(
        descriptors: impl IntoIterator<Item = &'static ResourceTypeDescriptor>,
    ) -> Result<Self, Vec<String>> {
        Self::from_shared(
            descriptors
                .into_iter()
                .map(|descriptor| Arc::new(descriptor.clone())),
        )
    }

    /// A registry of shared descriptors, static or declared, in order, such
    /// as another registry's [`descriptors`](Self::descriptors) followed by
    /// declared types.
    pub fn from_shared(
        descriptors: impl IntoIterator<Item = Arc<ResourceTypeDescriptor>>,
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
            if !descriptor.is_canonical_target(descriptor.example()) {
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
            for attribute in descriptor.attributes() {
                let name = attribute.name();
                if name.is_empty()
                    || name.len() > 64
                    || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    || !attribute_names.insert(name)
                {
                    errors.push(format!(
                        "resource type {} has invalid or duplicate attribute names",
                        descriptor.id
                    ));
                }
            }
            if types.contains_key(&descriptor.id) {
                errors.push(format!(
                    "resource type {} is registered more than once",
                    descriptor.id
                ));
            } else {
                types.insert(descriptor.id.clone(), Arc::clone(&descriptor));
                order.push(descriptor);
            }
        }
        if errors.is_empty() {
            Ok(Self { types, order })
        } else {
            Err(errors)
        }
    }

    pub fn get(&self, id: &ResourceType) -> Option<&Arc<ResourceTypeDescriptor>> {
        self.types.get(id)
    }

    pub fn descriptors(&self) -> impl Iterator<Item = &Arc<ResourceTypeDescriptor>> + '_ {
        self.order.iter()
    }

    pub fn ids(&self) -> impl Iterator<Item = &ResourceType> + '_ {
        self.order.iter().map(|descriptor| &descriptor.id)
    }

    pub fn metadata(&self) -> Vec<ResourceTypeMetadata> {
        self.descriptors()
            .map(|descriptor| descriptor.metadata())
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
pub static GIT_REPOSITORY_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("git_repository"),
    "Git repository",
    "Git repositories",
    "engineering/payments",
    is_canonical_repository_path,
)
.with_namespace(NamespaceSelectorDescriptor::new(
    is_repository_selector_path,
    "Repositories under a namespace",
    "Repositories",
    "engineering/platform",
));

pub fn is_canonical_repository_path(value: &str) -> bool {
    is_repository_selector_path(value)
        && value.split('/').count() >= 2
        && !value.bytes().all(|byte| byte.is_ascii_digit())
}

#[non_exhaustive]
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

fn is_repository_selector_segment(segment: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn project_pattern() -> ResourcePattern {
        ResourcePattern::new("[A-Z][A-Z0-9]{1,9}", 256).unwrap()
    }

    fn declared_project() -> ResourceTypeDescriptor {
        ResourceTypeDescriptor::declared(
            ResourceType::new("ticketing_project").unwrap(),
            "Project",
            "Projects",
            "OPS",
            project_pattern(),
            vec![
                ResourceAttributeDescriptor::declared(
                    "region",
                    "Region",
                    "Hosting region.",
                    true,
                    Some(ResourcePattern::new("[a-z0-9-]{1,32}", 8192).unwrap()),
                ),
                ResourceAttributeDescriptor::declared(
                    "webhookSecret",
                    "Webhook secret",
                    "Per-project signing secret.",
                    false,
                    None,
                ),
            ],
        )
    }

    fn exact(value: &str) -> ResourceSelector {
        ResourceSelector::Exact {
            value: value.into(),
        }
    }

    fn attributes(values: &[(&str, &str)]) -> ResourceAttributes {
        values
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>()
            .into()
    }

    #[test]
    fn resource_patterns_match_whole_bounded_values() {
        let pattern = project_pattern();
        assert!(pattern.is_match("OPS"));
        assert!(!pattern.is_match("OPS-1"));
        assert!(!pattern.is_match("xOPS"));
        assert!(!pattern.is_match("OPS\n"));
        assert!(!pattern.is_match(""));
        // A declared multi-line flag stays inside the anchors.
        let multiline = ResourcePattern::new("(?m)^[a-z]+$", 64).unwrap();
        assert!(multiline.is_match("abc"));
        assert!(!multiline.is_match("abc\ndef"));
        // An alternation is anchored as a whole.
        let alternation = ResourcePattern::new("a|ab", 8).unwrap();
        assert!(alternation.is_match("ab"));
        assert!(!alternation.is_match("abc"));
        let bounded = ResourcePattern::new("[a-z]+", 3).unwrap();
        assert!(bounded.is_match("abc"));
        assert!(!bounded.is_match("abcd"));
        assert_eq!(bounded.source(), "[a-z]+");
        assert_eq!(bounded.max_length(), 3);
    }

    #[test]
    fn resource_patterns_reject_invalid_or_unbounded_sources() {
        for (source, max_length, message) in [
            ("", 8, "must not be empty"),
            ("(unclosed", 8, "not a valid regular expression"),
            ("(a)\\1", 8, "not a valid regular expression"),
            ("(?=a)a", 8, "not a valid regular expression"),
            ("[a-z]+", 0, "maximum length"),
            ("[a-z]+", 8193, "maximum length"),
            ("\\w{1000}\\w{1000}\\w{1000}", 8192, "compilation budget"),
        ] {
            let error = ResourcePattern::new(source, max_length).unwrap_err();
            assert!(error.contains(message), "{source}: {error}");
        }
        let long = "a".repeat(8 * 1024 + 1);
        assert!(
            ResourcePattern::new(long, 8)
                .unwrap_err()
                .contains("exceeds 8192 bytes")
        );
        // Verbose-mode whitespace counts toward the source bound only.
        let padded = format!("(?x)a{}", " ".repeat(8 * 1024 - 5));
        assert!(ResourcePattern::new(padded, 8192).unwrap().is_match("a"));
    }

    #[test]
    fn resource_patterns_compare_by_source_and_bound() {
        assert_eq!(project_pattern(), project_pattern());
        assert_ne!(
            project_pattern(),
            ResourcePattern::new("[A-Z][A-Z0-9]{1,9}", 255).unwrap()
        );
        assert_ne!(
            project_pattern(),
            ResourcePattern::new("[A-Z][A-Z0-9]{1,8}", 256).unwrap()
        );
        assert_eq!(
            format!("{:?}", ResourcePattern::new("[a-z]+", 3).unwrap()),
            r#"ResourcePattern { source: "[a-z]+", max_length: 3 }"#
        );
    }

    #[test]
    fn declared_resource_types_use_their_pattern_labels_and_attributes() {
        let project = declared_project();
        assert_eq!(project.id().as_str(), "ticketing_project");
        assert_eq!(project.label(), "Project");
        assert_eq!(project.plural_label(), "Projects");
        assert_eq!(project.example(), "OPS");
        assert_eq!(project.pattern(), Some(&project_pattern()));
        assert!(project.namespace().is_none());
        assert_eq!(project.selector_kinds(), ["exact", "all"]);
        assert!(project.accepts(&exact("OPS")));
        assert!(project.accepts(&ResourceSelector::All));
        assert!(!project.accepts(&exact("ops")));
        assert!(!project.accepts(&ResourceSelector::Namespace {
            value: "OPS".into()
        }));
        let [region, secret] = project.attributes() else {
            panic!("two declared attributes");
        };
        assert_eq!(
            (region.name(), region.label(), region.description()),
            ("region", "Region", "Hosting region.")
        );
        assert!(region.is_required());
        assert_eq!(
            region.pattern().map(ResourcePattern::source),
            Some("[a-z0-9-]{1,32}")
        );
        assert!(!secret.is_required());
        assert!(secret.pattern().is_none());
        assert!(secret.is_valid("any value at all"));

        let metadata = project.metadata();
        assert_eq!(metadata.selectors, ["exact", "all"]);
        assert_eq!(metadata.attributes.len(), 2);
        assert!(metadata.attributes.iter().all(|attribute| attribute.secret));
        assert_eq!(metadata.attributes[1].name, "webhookSecret");
    }

    #[test]
    fn declared_resource_attributes_validate_from_the_declaration() {
        let project = declared_project();
        let target = exact("OPS");
        assert!(
            project
                .validate_attributes(&target, &attributes(&[("region", "eu-1")]), true)
                .is_ok()
        );
        assert!(
            project
                .validate_attributes(
                    &target,
                    &attributes(&[("region", "eu-1"), ("webhookSecret", "s3cr3t")]),
                    true,
                )
                .is_ok()
        );
        for (values, require_all, message) in [
            (
                vec![("region", "EU_1")],
                true,
                "resource attribute region is invalid",
            ),
            (
                vec![("region", "")],
                true,
                "resource attribute region is invalid",
            ),
            (vec![("unknown", "x")], false, "unknown resource attribute"),
            (
                vec![("webhookSecret", "x")],
                true,
                "required resource attributes are missing",
            ),
        ] {
            assert_eq!(
                project
                    .validate_attributes(&target, &attributes(&values), require_all)
                    .unwrap_err(),
                message
            );
        }
        let oversized = "x".repeat(8193);
        assert_eq!(
            project
                .validate_attributes(
                    &target,
                    &attributes(&[("region", "eu-1"), ("webhookSecret", &oversized)]),
                    true,
                )
                .unwrap_err(),
            "resource attribute webhookSecret is invalid"
        );
        // A patch may omit a required attribute it does not change.
        assert!(
            project
                .validate_attributes(&target, &attributes(&[("webhookSecret", "x")]), false)
                .is_ok()
        );
        assert_eq!(
            project
                .validate_attributes(
                    &ResourceSelector::All,
                    &attributes(&[("region", "eu-1")]),
                    false,
                )
                .unwrap_err(),
            "private attributes require an exact resource"
        );
    }

    #[test]
    fn registries_share_static_and_declared_descriptors() {
        let composition = ResourceTypeRegistry::new([&GIT_REPOSITORY_RESOURCE]).unwrap();
        let declared = Arc::new(declared_project());
        let effective = ResourceTypeRegistry::from_shared(
            composition
                .descriptors()
                .cloned()
                .chain([Arc::clone(&declared)]),
        )
        .unwrap();
        assert_eq!(
            effective
                .ids()
                .map(ResourceType::as_str)
                .collect::<Vec<_>>(),
            ["git_repository", "ticketing_project"]
        );
        let shared = effective.get(declared.id()).unwrap();
        assert!(Arc::ptr_eq(shared, &declared));
        assert!(Arc::ptr_eq(
            effective.get(GIT_REPOSITORY_RESOURCE.id()).unwrap(),
            composition.get(GIT_REPOSITORY_RESOURCE.id()).unwrap(),
        ));
        assert!(
            effective
                .validate_selector("ops", declared.id(), &exact("OPS"))
                .is_ok()
        );
        assert_eq!(
            effective
                .validate_selector("ops", declared.id(), &exact("ops"))
                .unwrap_err(),
            "resource ops selector is invalid for ticketing_project"
        );
        assert_eq!(effective.metadata()[1].label, "Project");
        // The composition registry is unchanged.
        assert!(composition.get(declared.id()).is_none());
    }

    #[test]
    fn registries_validate_declared_descriptors() {
        let declared = |example: &str, attributes: Vec<ResourceAttributeDescriptor>| {
            Arc::new(ResourceTypeDescriptor::declared(
                ResourceType::new("ticketing_project").unwrap(),
                "Project",
                "Projects",
                example,
                project_pattern(),
                attributes,
            ))
        };
        let attribute = |name: &str| {
            ResourceAttributeDescriptor::declared(name, "Label", "Description.", false, None)
        };
        assert_eq!(
            ResourceTypeRegistry::from_shared([declared("ops", Vec::new())]).unwrap_err(),
            ["resource type ticketing_project example is not a canonical target"]
        );
        assert_eq!(
            ResourceTypeRegistry::from_shared([declared(
                "OPS",
                vec![attribute("region"), attribute("region")],
            )])
            .unwrap_err(),
            ["resource type ticketing_project has invalid or duplicate attribute names"]
        );
        assert_eq!(
            ResourceTypeRegistry::from_shared([declared("OPS", vec![attribute("bad-name")])])
                .unwrap_err(),
            ["resource type ticketing_project has invalid or duplicate attribute names"]
        );
        assert_eq!(
            ResourceTypeRegistry::from_shared([
                declared("OPS", Vec::new()),
                declared("OPS", Vec::new()),
            ])
            .unwrap_err(),
            ["resource type ticketing_project is registered more than once"]
        );
        let static_duplicate = ResourceTypeRegistry::from_shared([
            Arc::new(GIT_REPOSITORY_RESOURCE.clone()),
            Arc::new(ResourceTypeDescriptor::declared(
                GIT_REPOSITORY_RESOURCE.id().clone(),
                "Repository",
                "Repositories",
                "a/b",
                ResourcePattern::new("[a-z]+/[a-z]+", 64).unwrap(),
                Vec::new(),
            )),
        ])
        .unwrap_err();
        assert_eq!(
            static_duplicate,
            ["resource type git_repository is registered more than once"]
        );
    }

    #[test]
    #[should_panic(expected = "a declared resource type takes its attributes at construction")]
    fn declared_resource_types_reject_static_attribute_lists() {
        static ATTRIBUTES: [ResourceAttributeDescriptor; 1] =
            [ResourceAttributeDescriptor::optional(
                "region",
                "Region",
                "Hosting region.",
                |value| !value.is_empty(),
            )];
        let _ = declared_project().with_attributes(&ATTRIBUTES);
    }

    #[test]
    fn static_resource_types_keep_their_const_form() {
        static ATTRIBUTES: [ResourceAttributeDescriptor; 1] =
            [ResourceAttributeDescriptor::required(
                "url",
                "URL",
                "Destination.",
                |value| value.starts_with("https://"),
            )];
        static TYPE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
            ResourceType::from_static("example_destination"),
            "Destination",
            "Destinations",
            "alerts",
            |value| !value.is_empty() && !value.contains('/'),
        )
        .with_attributes(&ATTRIBUTES);
        const LABEL_LENGTH: usize = TYPE.label().len();
        const ATTRIBUTE_COUNT: usize = TYPE.attributes().len();
        assert_eq!((LABEL_LENGTH, ATTRIBUTE_COUNT), (11, 1));
        assert!(TYPE.pattern().is_none());
        assert!(TYPE.attributes()[0].pattern().is_none());
        assert!(TYPE.attributes()[0].is_valid("https://hooks.example.test"));
        assert!(!TYPE.attributes()[0].is_valid("http://hooks.example.test"));
        let registry = ResourceTypeRegistry::new([&TYPE]).unwrap();
        assert_eq!(registry.get(TYPE.id()).unwrap().label(), "Destination");
    }
}
