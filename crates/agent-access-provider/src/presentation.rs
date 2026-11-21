//! Bounded selection of declared rich-content fields in otherwise unchanged JSON.
//!
//! Resolve request controls once against the admitted action. The resulting
//! [`ResolvedPresentation`] pins the concrete format and its body declarations.
use crate::{ProviderError, ReasonCode};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use thiserror::Error;

pub const OUTPUT_CONTENT_FORMATS: &[OutputContentFormat] = &[
    OutputContentFormat::Markdown,
    OutputContentFormat::Text,
    OutputContentFormat::Adf,
    OutputContentFormat::Storage,
];
pub const RENDER_FAILURE_MESSAGE: &str = "provider response content could not be rendered safely";
const MAX_REQUEST_RENDER_NODES: usize = 131_072;
const MAX_REQUEST_RENDER_WORK_UNITS: usize = 524_288;
const MAX_BODY_FIELDS: usize = 64;
const MAX_POINTER_BYTES: usize = 2_048;
const MAX_PATH_SEGMENTS: usize = 32;
const MAX_FIELD_BYTES: usize = 128;

/// A concrete body representation. Downstream codecs reject unknown variants;
/// omission is represented separately and there is no global default.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum OutputContentFormat {
    Markdown,
    Text,
    Adf,
    Storage,
}
impl OutputContentFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::Text => "text",
            Self::Adf => "adf",
            Self::Storage => "storage",
        }
    }
}

/// One representation with a constructor-enforced value type.
#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct SelectedContent {
    format: OutputContentFormat,
    value: Value,
}
impl std::fmt::Debug for SelectedContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedContent")
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}
impl SelectedContent {
    pub fn markdown(value: impl Into<String>) -> Self {
        Self {
            format: OutputContentFormat::Markdown,
            value: Value::String(value.into()),
        }
    }
    pub fn text(value: impl Into<String>) -> Self {
        Self {
            format: OutputContentFormat::Text,
            value: Value::String(value.into()),
        }
    }
    pub fn adf(value: Map<String, Value>) -> Self {
        Self {
            format: OutputContentFormat::Adf,
            value: Value::Object(value),
        }
    }
    pub fn storage(value: impl Into<String>) -> Self {
        Self {
            format: OutputContentFormat::Storage,
            value: Value::String(value.into()),
        }
    }
    pub const fn format(&self) -> OutputContentFormat {
        self.format
    }
    pub const fn value(&self) -> &Value {
        &self.value
    }
    pub fn into_value(self) -> Value {
        let mut fields = Map::new();
        fields.insert("format".into(), Value::String(self.format.as_str().into()));
        fields.insert("value".into(), self.value);
        Value::Object(fields)
    }
}

/// Unresolved request controls. Present nulls are invalid; only omission means
/// that the caller did not supply a selector or preference.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseOptions {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_format"
    )]
    pub output_content_format: Option<OutputContentFormat>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_format"
    )]
    pub preferred_output_content_format: Option<OutputContentFormat>,
}
fn present_format<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<OutputContentFormat>, D::Error> {
    OutputContentFormat::deserialize(deserializer).map(Some)
}
impl ResponseOptions {
    pub const fn new(
        exact: Option<OutputContentFormat>,
        preferred: Option<OutputContentFormat>,
    ) -> Self {
        Self {
            output_content_format: exact,
            preferred_output_content_format: preferred,
        }
    }
}

/// Shared defensive accounting for every rich-content document in one request.
#[derive(Debug)]
pub struct RenderBudget {
    remaining_nodes: usize,
    remaining_work_units: usize,
}
impl Default for RenderBudget {
    fn default() -> Self {
        Self::with_limits(MAX_REQUEST_RENDER_NODES, MAX_REQUEST_RENDER_WORK_UNITS)
    }
}
impl RenderBudget {
    pub fn with_limits(nodes: usize, work_units: usize) -> Self {
        Self {
            remaining_nodes: nodes,
            remaining_work_units: work_units,
        }
    }
    pub fn remaining_nodes(&self) -> usize {
        self.remaining_nodes
    }
    pub fn remaining_work_units(&self) -> usize {
        self.remaining_work_units
    }
    pub fn charge_node(&mut self) -> Result<(), RenderBudgetExhausted> {
        self.remaining_nodes = self
            .remaining_nodes
            .checked_sub(1)
            .ok_or(RenderBudgetExhausted::Nodes)?;
        Ok(())
    }
    pub fn charge_work(&mut self, units: usize) -> Result<(), RenderBudgetExhausted> {
        self.remaining_work_units = self
            .remaining_work_units
            .checked_sub(units)
            .ok_or(RenderBudgetExhausted::WorkUnits)?;
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("provider response content could not be rendered safely")]
pub struct RenderError;
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RenderBudgetExhausted {
    #[error("rich-content node budget exhausted")]
    Nodes,
    #[error("rich-content work budget exhausted")]
    WorkUnits,
}

/// Static body declarations and concrete capabilities for one action.
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct ActionPresentation {
    embedded_bodies: &'static [EmbeddedBody],
    output_content_formats: &'static [OutputContentFormat],
    native_output_content_format: OutputContentFormat,
}
impl ActionPresentation {
    pub const fn new(
        bodies: &'static [EmbeddedBody],
        formats: &'static [OutputContentFormat],
        native: OutputContentFormat,
    ) -> Self {
        Self {
            embedded_bodies: bodies,
            output_content_formats: formats,
            native_output_content_format: native,
        }
    }
    pub const fn embedded_bodies(&self) -> &'static [EmbeddedBody] {
        self.embedded_bodies
    }
    pub const fn output_content_formats(&self) -> &'static [OutputContentFormat] {
        self.output_content_formats
    }
    pub const fn native_output_content_format(&self) -> OutputContentFormat {
        self.native_output_content_format
    }
    pub fn body_fields(&self) -> Vec<BodyField> {
        self.embedded_bodies
            .iter()
            .map(EmbeddedBody::body_field)
            .collect()
    }
    pub fn validate(&self) -> Result<(), RenderError> {
        if self.embedded_bodies.is_empty()
            || self.embedded_bodies.len() > MAX_BODY_FIELDS
            || self.output_content_formats.is_empty()
            || self.output_content_formats.len() > OUTPUT_CONTENT_FORMATS.len()
            || !self
                .output_content_formats
                .contains(&self.native_output_content_format)
            || self
                .output_content_formats
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.output_content_formats.len()
        {
            return Err(RenderError);
        }
        for body in self.embedded_bodies {
            if body.owner_path.len() >= MAX_PATH_SEGMENTS
                || body.owner_equals.len() > 4
                || body.owner_path.iter().any(|segment| {
                    matches!(
                        segment,
                        BodyPathSegment::Field("*")
                            | BodyPathSegment::OptionalField("*")
                            | BodyPathSegment::NullableField("*")
                            | BodyPathSegment::OptionalNullableField("*")
                    )
                })
                || body
                    .owner_equals
                    .iter()
                    .map(|(key, _)| key)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != body.owner_equals.len()
                || self
                    .output_content_formats
                    .iter()
                    .any(|format| !body.codec.supported_formats().contains(format))
            {
                return Err(RenderError);
            }
        }
        validate_body_fields(&self.body_fields())
    }
}
impl std::fmt::Debug for ActionPresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionPresentation")
            .field("embedded_bodies", &self.embedded_bodies)
            .field("output_content_formats", &self.output_content_formats)
            .field(
                "native_output_content_format",
                &self.native_output_content_format,
            )
            .finish()
    }
}
impl PartialEq for ActionPresentation {
    fn eq(&self, other: &Self) -> bool {
        self.embedded_bodies == other.embedded_bodies
            && self.output_content_formats == other.output_content_formats
            && self.native_output_content_format == other.native_output_content_format
    }
}

/// A field to replace in each owner selected by a static path.
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct EmbeddedBody {
    owner_path: &'static [BodyPathSegment],
    field: &'static str,
    optional: bool,
    nullable: bool,
    owner_equals: &'static [(&'static str, &'static str)],
    codec: &'static dyn EmbeddedBodyCodec,
}
impl EmbeddedBody {
    pub const fn new(
        owner_path: &'static [BodyPathSegment],
        field: &'static str,
        codec: &'static dyn EmbeddedBodyCodec,
    ) -> Self {
        Self {
            owner_path,
            field,
            codec,
            optional: false,
            nullable: false,
            owner_equals: &[],
        }
    }
    pub const fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
    pub const fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }
    pub const fn owner_equals(
        mut self,
        predicates: &'static [(&'static str, &'static str)],
    ) -> Self {
        self.owner_equals = predicates;
        self
    }
    pub const fn owner_path(&self) -> &'static [BodyPathSegment] {
        self.owner_path
    }
    pub const fn field(&self) -> &'static str {
        self.field
    }
    pub const fn is_optional(&self) -> bool {
        self.optional
    }
    pub const fn is_nullable(&self) -> bool {
        self.nullable
    }
    pub const fn codec(&self) -> &'static dyn EmbeddedBodyCodec {
        self.codec
    }
    pub fn body_field(&self) -> BodyField {
        let mut field = BodyField::new("/result", self.field);
        field.optional = self.optional;
        field.nullable = self.nullable;
        for segment in self.owner_path {
            field.owner_path.push_str(&segment.pointer_segment());
            if matches!(
                segment,
                BodyPathSegment::OptionalField(_) | BodyPathSegment::OptionalNullableField(_)
            ) {
                field.optional_owner_prefixes.push(field.owner_path.clone());
            }
            if matches!(
                segment,
                BodyPathSegment::NullableField(_) | BodyPathSegment::OptionalNullableField(_)
            ) {
                field.nullable_owner_prefixes.push(field.owner_path.clone());
            }
        }
        if !self.owner_equals.is_empty() {
            field.owner_equals = Some(
                self.owner_equals
                    .iter()
                    .map(|(key, value)| ((*key).into(), (*value).into()))
                    .collect(),
            );
        }
        field
    }
}
impl std::fmt::Debug for EmbeddedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedBody")
            .field("owner_path", &self.owner_path)
            .field("field", &self.field)
            .field("optional", &self.optional)
            .field("nullable", &self.nullable)
            .field("owner_equals", &self.owner_equals)
            .finish_non_exhaustive()
    }
}
impl PartialEq for EmbeddedBody {
    fn eq(&self, other: &Self) -> bool {
        self.owner_path == other.owner_path
            && self.field == other.field
            && self.optional == other.optional
            && self.nullable == other.nullable
            && self.owner_equals == other.owner_equals
            && std::ptr::addr_eq(self.codec, other.codec)
    }
}
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyPathSegment {
    Field(&'static str),
    OptionalField(&'static str),
    NullableField(&'static str),
    OptionalNullableField(&'static str),
    Each,
}
impl BodyPathSegment {
    fn pointer_segment(&self) -> String {
        match self {
            Self::Field(field)
            | Self::OptionalField(field)
            | Self::NullableField(field)
            | Self::OptionalNullableField(field) => format!("/{}", escape_pointer(field)),
            Self::Each => "/*".into(),
        }
    }
}
/// Validate fetched native sources and select one representation. `None` removes
/// an optional field; malformed sources and exhausted budgets never fall back.
pub trait EmbeddedBodyCodec: Sync {
    fn supported_formats(&self) -> &'static [OutputContentFormat];
    fn select(
        &self,
        source: &Value,
        format: OutputContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<SelectedContent>, RenderError>;
}

/// Serializable path contract, rooted at the complete Broker envelope.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BodyField {
    pub owner_path: String,
    pub optional_owner_prefixes: Vec<String>,
    pub nullable_owner_prefixes: Vec<String>,
    pub field: String,
    pub optional: bool,
    pub nullable: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_owner_equals"
    )]
    pub owner_equals: Option<BTreeMap<String, String>>,
}

fn present_owner_equals<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, String>>, D::Error> {
    BTreeMap::<String, String>::deserialize(deserializer).map(Some)
}

impl BodyField {
    pub fn new(owner_path: impl Into<String>, field: impl Into<String>) -> Self {
        Self {
            owner_path: owner_path.into(),
            field: field.into(),
            optional_owner_prefixes: Vec::new(),
            nullable_owner_prefixes: Vec::new(),
            optional: false,
            nullable: false,
            owner_equals: None,
        }
    }
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
    pub fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }
    pub fn with_optional_owner_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.optional_owner_prefixes = prefixes;
        self
    }
    pub fn with_nullable_owner_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.nullable_owner_prefixes = prefixes;
        self
    }
    pub fn with_owner_equals(mut self, predicates: BTreeMap<String, String>) -> Self {
        self.owner_equals = Some(predicates);
        self
    }
}
fn escape_pointer(field: &str) -> String {
    field.replace('~', "~0").replace('/', "~1")
}
fn pointer_parts(pointer: &str) -> Result<Vec<String>, RenderError> {
    if pointer.len() > MAX_POINTER_BYTES || !pointer.starts_with('/') {
        return Err(RenderError);
    }
    let raw: Vec<_> = pointer[1..].split('/').collect();
    if raw.len() > MAX_PATH_SEGMENTS || raw.first() != Some(&"result") {
        return Err(RenderError);
    }
    raw.iter()
        .map(|part| {
            let mut decoded = String::new();
            let mut chars = part.chars();
            while let Some(ch) = chars.next() {
                if ch == '~' {
                    decoded.push(match chars.next() {
                        Some('0') => '~',
                        Some('1') => '/',
                        _ => return Err(RenderError),
                    });
                } else {
                    decoded.push(ch);
                }
            }
            if decoded.is_empty()
                || decoded.len() > MAX_FIELD_BYTES
                || decoded.chars().any(char::is_control)
            {
                return Err(RenderError);
            }
            Ok(decoded)
        })
        .collect()
}
/// Reject malformed, unbounded or duplicate selected-body locations.
pub fn validate_body_fields(fields: &[BodyField]) -> Result<(), RenderError> {
    if fields.len() > MAX_BODY_FIELDS {
        return Err(RenderError);
    }
    let mut locations = BTreeSet::new();
    for field in fields {
        let parts = pointer_parts(&field.owner_path)?;
        if field.field.is_empty()
            || field.field.len() > MAX_FIELD_BYTES
            || field.field.chars().any(char::is_control)
            || !locations.insert((field.owner_path.as_str(), field.field.as_str()))
        {
            return Err(RenderError);
        }
        for prefixes in [
            &field.optional_owner_prefixes,
            &field.nullable_owner_prefixes,
        ] {
            if prefixes.len() > parts.len() {
                return Err(RenderError);
            }
            let mut unique = BTreeSet::new();
            for prefix in prefixes {
                pointer_parts(prefix)?;
                if !unique.insert(prefix)
                    || !(field.owner_path == *prefix
                        || field
                            .owner_path
                            .strip_prefix(prefix)
                            .is_some_and(|rest| rest.starts_with('/')))
                {
                    return Err(RenderError);
                }
            }
        }
        if let Some(predicates) = &field.owner_equals
            && (predicates.is_empty()
                || predicates.len() > 4
                || predicates.iter().any(|(key, value)| {
                    key.is_empty()
                        || key.len() > MAX_FIELD_BYTES
                        || value.len() > MAX_FIELD_BYTES
                        || key.chars().chain(value.chars()).any(char::is_control)
                }))
        {
            return Err(RenderError);
        }
    }
    Ok(())
}

/// Validate only declared bodies in a full success envelope. A preference does
/// not assume that an earlier catalog's capability set survived a reload.
pub fn validate_selected_content(
    envelope: &Value,
    fields: &[BodyField],
    exact: Option<OutputContentFormat>,
) -> Result<(), RenderError> {
    validate_body_fields(fields)?;
    for field in fields {
        visit_wire_owners(
            envelope,
            &pointer_parts(&field.owner_path)?,
            "",
            field,
            &mut |owner| {
                let owner = owner.as_object().ok_or(RenderError)?;
                if field.owner_equals.as_ref().is_some_and(|predicates| {
                    predicates.iter().any(|(key, value)| {
                        owner.get(key).and_then(Value::as_str) != Some(value.as_str())
                    })
                }) {
                    return Ok(());
                }
                let Some(value) = owner.get(&field.field) else {
                    return if field.optional {
                        Ok(())
                    } else {
                        Err(RenderError)
                    };
                };
                if value.is_null() {
                    return if field.nullable {
                        Ok(())
                    } else {
                        Err(RenderError)
                    };
                }
                let selected = value
                    .as_object()
                    .filter(|object| object.len() == 2)
                    .ok_or(RenderError)?;
                let format = match selected.get("format").and_then(Value::as_str) {
                    Some("markdown") => OutputContentFormat::Markdown,
                    Some("text") => OutputContentFormat::Text,
                    Some("adf") => OutputContentFormat::Adf,
                    Some("storage") => OutputContentFormat::Storage,
                    _ => return Err(RenderError),
                };
                if exact.is_some_and(|expected| expected != format) {
                    return Err(RenderError);
                }
                let selected_value = selected.get("value").ok_or(RenderError)?;
                match format {
                    OutputContentFormat::Adf if selected_value.is_object() => Ok(()),
                    OutputContentFormat::Markdown
                    | OutputContentFormat::Text
                    | OutputContentFormat::Storage
                        if selected_value.is_string() =>
                    {
                        Ok(())
                    }
                    _ => Err(RenderError),
                }
            },
        )?;
    }
    Ok(())
}
fn visit_wire_owners(
    value: &Value,
    parts: &[String],
    pointer: &str,
    field: &BodyField,
    visitor: &mut impl FnMut(&Value) -> Result<(), RenderError>,
) -> Result<(), RenderError> {
    if value.is_null()
        && field
            .nullable_owner_prefixes
            .iter()
            .any(|prefix| prefix == pointer)
    {
        return Ok(());
    }
    let Some((part, rest)) = parts.split_first() else {
        return visitor(value);
    };
    let next = format!("{pointer}/{}", escape_pointer(part));
    if part == "*" {
        for child in value.as_array().ok_or(RenderError)? {
            visit_wire_owners(child, rest, &next, field, visitor)?;
        }
        Ok(())
    } else {
        let owner = value.as_object().ok_or(RenderError)?;
        match owner.get(part) {
            Some(child) => visit_wire_owners(child, rest, &next, field, visitor),
            None if field.optional_owner_prefixes.contains(&next) => Ok(()),
            None => Err(RenderError),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseCapabilities {
    pub output_content_formats: Option<&'static [OutputContentFormat]>,
    pub native_output_content_format: Option<OutputContentFormat>,
    pub default_output_content_format: Option<OutputContentFormat>,
}
impl ResponseCapabilities {
    pub const fn new(
        formats: Option<&'static [OutputContentFormat]>,
        native: Option<OutputContentFormat>,
        default: Option<OutputContentFormat>,
    ) -> Self {
        Self {
            output_content_formats: formats,
            native_output_content_format: native,
            default_output_content_format: default,
        }
    }
    pub fn supports_output_content(self) -> bool {
        self.output_content_formats.is_some()
    }
}
pub fn response_capabilities(
    presentation: Option<&ActionPresentation>,
    preference: Option<OutputContentFormat>,
) -> ResponseCapabilities {
    let Some(presentation) = presentation else {
        return ResponseCapabilities::new(None, None, None);
    };
    let selected = preferred_format(presentation, preference);
    ResponseCapabilities::new(
        Some(presentation.output_content_formats),
        Some(presentation.native_output_content_format),
        Some(selected),
    )
}
fn preferred_format(
    presentation: &ActionPresentation,
    preference: Option<OutputContentFormat>,
) -> OutputContentFormat {
    let preferred = preference.unwrap_or(OutputContentFormat::Markdown);
    if presentation.output_content_formats.contains(&preferred) {
        preferred
    } else {
        presentation.native_output_content_format
    }
}

/// Concrete format and matching descriptor from the same admission snapshot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResolvedPresentation {
    presentation: Option<ActionPresentation>,
    output_content_format: Option<OutputContentFormat>,
}
impl ResolvedPresentation {
    pub const fn presentation(&self) -> Option<&ActionPresentation> {
        self.presentation.as_ref()
    }
    pub const fn output_content_format(&self) -> Option<OutputContentFormat> {
        self.output_content_format
    }
}
pub fn resolve_response_options(
    presentation: Option<ActionPresentation>,
    service_preference: Option<OutputContentFormat>,
    requested: ResponseOptions,
) -> Result<ResolvedPresentation, ProviderError> {
    if let Some(presentation) = &presentation {
        presentation.validate().map_err(|_| render_failure())?;
    }
    let output_content_format = if let Some(exact) = requested.output_content_format {
        if !presentation
            .as_ref()
            .is_some_and(|presentation| presentation.output_content_formats.contains(&exact))
        {
            return Err(unsupported());
        }
        Some(exact)
    } else {
        presentation.as_ref().map(|presentation| {
            preferred_format(
                presentation,
                requested
                    .preferred_output_content_format
                    .or(service_preference),
            )
        })
    };
    Ok(ResolvedPresentation {
        presentation,
        output_content_format,
    })
}

/// Replace declared fields, sharing source complexity and selected-body byte
/// budgets, then bound the complete serialized result including its tags.
pub fn present_result(
    resolved: &ResolvedPresentation,
    result: &mut Value,
    max_body_bytes: u64,
    max_result_bytes: u64,
) -> Result<(), ProviderError> {
    if let (Some(presentation), Some(format)) =
        (&resolved.presentation, resolved.output_content_format)
    {
        let mut budget = RenderBudget::default();
        let mut remaining = max_result_bytes;
        for body in presentation.embedded_bodies {
            visit_owners_mut(result, body.owner_path, &mut |owner| {
                let owner = owner.as_object_mut().ok_or(RenderError)?;
                if body
                    .owner_equals
                    .iter()
                    .any(|(key, value)| owner.get(*key).and_then(Value::as_str) != Some(*value))
                {
                    return Ok(());
                }
                let Some(source) = owner.get(body.field) else {
                    return if body.optional {
                        Ok(())
                    } else {
                        Err(RenderError)
                    };
                };
                if source.is_null() {
                    return if body.nullable {
                        Ok(())
                    } else {
                        Err(RenderError)
                    };
                }
                match body
                    .codec
                    .select(source, format, max_body_bytes, &mut budget)?
                {
                    Some(selected) => {
                        if selected.format != format {
                            return Err(RenderError);
                        }
                        let bytes = serialized_size_bounded(&selected, remaining)?;
                        remaining = remaining.checked_sub(bytes).ok_or(RenderError)?;
                        owner.insert(body.field.into(), selected.into_value());
                    }
                    None if body.optional => {
                        owner.remove(body.field);
                    }
                    None => return Err(RenderError),
                }
                Ok(())
            })
            .map_err(|_| render_failure())?;
        }
    }
    enforce_serialized_bound(result, max_result_bytes).map_err(|_| render_failure())
}
fn visit_owners_mut(
    value: &mut Value,
    path: &[BodyPathSegment],
    visitor: &mut impl FnMut(&mut Value) -> Result<(), RenderError>,
) -> Result<(), RenderError> {
    let Some((segment, rest)) = path.split_first() else {
        return visitor(value);
    };
    match segment {
        BodyPathSegment::Each => {
            for child in value.as_array_mut().ok_or(RenderError)? {
                visit_owners_mut(child, rest, visitor)?;
            }
            Ok(())
        }
        BodyPathSegment::Field(field)
        | BodyPathSegment::OptionalField(field)
        | BodyPathSegment::NullableField(field)
        | BodyPathSegment::OptionalNullableField(field) => {
            let object = value.as_object_mut().ok_or(RenderError)?;
            let Some(child) = object.get_mut(*field) else {
                return if matches!(
                    segment,
                    BodyPathSegment::OptionalField(_) | BodyPathSegment::OptionalNullableField(_)
                ) {
                    Ok(())
                } else {
                    Err(RenderError)
                };
            };
            if child.is_null()
                && matches!(
                    segment,
                    BodyPathSegment::NullableField(_) | BodyPathSegment::OptionalNullableField(_)
                )
            {
                return Ok(());
            }
            visit_owners_mut(child, rest, visitor)
        }
    }
}
fn unsupported() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ResponseFormatUnsupported,
        "requested response format is not supported for this action",
    )
}
fn render_failure() -> ProviderError {
    ProviderError::error(ReasonCode::UpstreamProtocolFailed, RENDER_FAILURE_MESSAGE)
}
fn serialized_size_bounded(value: &impl Serialize, max_bytes: u64) -> Result<u64, RenderError> {
    struct LimitWriter {
        written: u64,
        max_bytes: u64,
    }
    impl Write for LimitWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.written = self
                .written
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| io::Error::other("serialized result limit exceeded"))?;
            if self.written > self.max_bytes {
                return Err(io::Error::other("serialized result limit exceeded"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = LimitWriter {
        written: 0,
        max_bytes,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| RenderError)?;
    Ok(writer.written)
}
pub fn enforce_serialized_bound(value: &Value, max_bytes: u64) -> Result<(), RenderError> {
    serialized_size_bounded(value, max_bytes).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const TEXT_FORMATS: &[OutputContentFormat] =
        &[OutputContentFormat::Markdown, OutputContentFormat::Text];
    struct TextCodec;
    impl EmbeddedBodyCodec for TextCodec {
        fn supported_formats(&self) -> &'static [OutputContentFormat] {
            TEXT_FORMATS
        }
        fn select(
            &self,
            source: &Value,
            format: OutputContentFormat,
            max_body_bytes: u64,
            budget: &mut RenderBudget,
        ) -> Result<Option<SelectedContent>, RenderError> {
            let text = source.as_str().ok_or(RenderError)?;
            if text.len() as u64 > max_body_bytes {
                return Err(RenderError);
            }
            budget.charge_node().map_err(|_| RenderError)?;
            budget.charge_work(text.len()).map_err(|_| RenderError)?;
            match format {
                OutputContentFormat::Markdown => Ok(Some(SelectedContent::markdown(text))),
                OutputContentFormat::Text => Ok(Some(SelectedContent::text(text))),
                _ => Err(RenderError),
            }
        }
    }
    const ROOT: ActionPresentation = ActionPresentation::new(
        &[EmbeddedBody::new(&[], "body", &TextCodec)],
        TEXT_FORMATS,
        OutputContentFormat::Markdown,
    );
    fn resolve(
        presentation: ActionPresentation,
        exact: Option<OutputContentFormat>,
        preferred: Option<OutputContentFormat>,
    ) -> ResolvedPresentation {
        resolve_response_options(
            Some(presentation),
            None,
            ResponseOptions::new(exact, preferred),
        )
        .unwrap()
    }
    #[test]
    fn exact_and_soft_preferences_resolve_without_lower_tier_cascade() {
        use OutputContentFormat::*;
        for (exact, preferred, service, expected) in [
            (None, None, None, Markdown),
            (None, None, Some(Text), Text),
            (None, Some(Text), Some(Markdown), Text),
            (Some(Markdown), Some(Text), Some(Text), Markdown),
            (None, Some(Adf), Some(Text), Markdown),
            (None, None, Some(Storage), Markdown),
        ] {
            assert_eq!(
                resolve_response_options(
                    Some(ROOT),
                    service,
                    ResponseOptions::new(exact, preferred)
                )
                .unwrap()
                .output_content_format(),
                Some(expected)
            );
        }
        assert_eq!(
            resolve_response_options(
                Some(ROOT),
                None,
                ResponseOptions::new(Some(OutputContentFormat::Adf), None)
            )
            .unwrap_err()
            .reason_code,
            ReasonCode::ResponseFormatUnsupported
        );
        assert_eq!(
            response_capabilities(Some(&ROOT), Some(Text)).default_output_content_format,
            Some(Text)
        );
        assert_eq!(
            response_capabilities(Some(&ROOT), Some(Adf)).default_output_content_format,
            Some(Markdown)
        );
    }
    #[test]
    fn no_body_actions_ignore_preferences_and_reject_exact_selection() {
        let resolved = resolve_response_options(
            None,
            Some(OutputContentFormat::Storage),
            ResponseOptions::new(None, Some(OutputContentFormat::Adf)),
        )
        .unwrap();
        assert_eq!(resolved.output_content_format(), None);
        let mut result =
            json!({"body":"ordinary field", "nested":{"outputContentFormat":"provider value"}});
        let original = result.clone();
        present_result(&resolved, &mut result, 1, 1024).unwrap();
        assert_eq!(result, original);
        assert!(present_result(&resolved, &mut result, 1, 2).is_err());
        assert!(
            resolve_response_options(
                None,
                None,
                ResponseOptions::new(Some(OutputContentFormat::Text), None)
            )
            .is_err()
        );
        assert!(!response_capabilities(None, None).supports_output_content());
    }
    #[test]
    fn options_reject_null_unknown_types_and_retired_fields() {
        assert_eq!(
            serde_json::from_value::<ResponseOptions>(json!({})).unwrap(),
            ResponseOptions::default()
        );
        for field in ["outputContentFormat", "preferredOutputContentFormat"] {
            for value in [
                Value::Null,
                json!("native"),
                json!("html"),
                json!(4),
                json!({}),
                json!([]),
                json!(false),
            ] {
                assert!(serde_json::from_value::<ResponseOptions>(json!({field:value})).is_err());
            }
        }
        for field in ["readContentFormat", "responseFormat"] {
            assert!(serde_json::from_value::<ResponseOptions>(json!({field:"markdown"})).is_err());
        }
        assert!(
            serde_json::from_value::<ResponseOptions>(
                json!({"outputContentFormat":"text","preferredOutputContentFormat":null})
            )
            .is_err()
        );
        assert_eq!(
            serde_json::to_value(ResponseOptions::default()).unwrap(),
            json!({})
        );
    }
    #[test]
    fn selected_constructors_enforce_value_types_and_do_not_debug_content() {
        let doc = json!({"type":"doc","version":1,"content":[]});
        assert_eq!(
            SelectedContent::adf(doc.as_object().unwrap().clone()).into_value(),
            json!({"format":"adf","value":doc})
        );
        for selected in [
            SelectedContent::markdown("private"),
            SelectedContent::text("private"),
            SelectedContent::storage("private"),
        ] {
            assert!(selected.value().is_string());
            assert!(!format!("{selected:?}").contains("private"));
            assert_eq!(
                serde_json::to_value(&selected).unwrap(),
                selected.into_value()
            );
        }
    }
    #[test]
    fn presentation_replaces_declared_field_once_and_preserves_metadata() {
        let mut result = json!({"id":42,"body":"é🙂","other":{"body":"raw"}});
        present_result(
            &resolve(ROOT, Some(OutputContentFormat::Text), None),
            &mut result,
            6,
            1024,
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"id":42,"body":{"format":"text","value":"é🙂"},"other":{"body":"raw"}})
        );
        validate_selected_content(
            &json!({"result":result}),
            &ROOT.body_fields(),
            Some(OutputContentFormat::Text),
        )
        .unwrap();
        assert!(present_result(&resolve(ROOT, None, None), &mut result, 6, 1024).is_err());
    }
    #[test]
    fn optional_nullable_and_predicate_owners_are_precise() {
        const PRESENTATION: ActionPresentation = ActionPresentation::new(
            &[EmbeddedBody::new(
                &[
                    BodyPathSegment::OptionalNullableField("page"),
                    BodyPathSegment::Field("items"),
                    BodyPathSegment::Each,
                ],
                "value",
                &TextCodec,
            )
            .optional()
            .nullable()
            .owner_equals(&[("status", "supported"), ("type", "text")])],
            TEXT_FORMATS,
            OutputContentFormat::Markdown,
        );
        for mut value in [
            json!({}),
            json!({"page":null}),
            json!({"page":{"items":[
                {"status":"unsupported","value":{"untouched":true}},
                {"status":"supported","type":"text"},
                {"status":"supported","type":"text","value":null},
                {"status":"supported","type":"text","value":""}
            ]}}),
        ] {
            present_result(&resolve(PRESENTATION, None, None), &mut value, 100, 2048).unwrap();
            validate_selected_content(&json!({"result":value}), &PRESENTATION.body_fields(), None)
                .unwrap();
        }
        for mut value in [
            json!({"page":4}),
            json!({"page":{}}),
            json!({"page":{"items":null}}),
            json!({"page":{"items":[null]}}),
        ] {
            assert!(
                present_result(&resolve(PRESENTATION, None, None), &mut value, 100, 2048).is_err()
            );
        }
        let field = PRESENTATION.body_fields().remove(0);
        assert_eq!(field.optional_owner_prefixes, ["/result/page"]);
        assert_eq!(field.nullable_owner_prefixes, ["/result/page"]);
    }
    #[test]
    fn client_validation_is_location_specific_and_accepts_new_concrete_formats() {
        let fields = ROOT.body_fields();
        let valid = json!({"result":{"body":{"format":"adf","value":{"type":"doc"}},"other":{"format":"future"}}});
        validate_selected_content(&valid, &fields, None).unwrap();
        assert!(
            validate_selected_content(&valid, &fields, Some(OutputContentFormat::Text)).is_err()
        );
        for invalid in [
            json!({"format":"adf","value":"{}"}),
            json!({"format":"text","value":{}}),
            json!({"format":"text","value":"x","extra":true}),
            json!({"format":"native","value":"x"}),
            json!({"format":"text"}),
            Value::Null,
        ] {
            assert!(
                validate_selected_content(&json!({"result":{"body":invalid}}), &fields, None)
                    .is_err()
            );
        }
        assert!(validate_selected_content(&json!({"result":{}}), &fields, None).is_err());
    }
    #[test]
    fn metadata_validates_prefixes_duplicates_predicates_and_required_fields() {
        let valid = BodyField::new("/result/a~1b/*/c~0d", "literal/*").optional();
        validate_body_fields(std::slice::from_ref(&valid)).unwrap();
        assert!(validate_body_fields(&[valid.clone(), valid.clone()]).is_err());
        for pointer in [
            "result",
            "/other",
            "/result/bad~",
            "/result/~2",
            "/result//a",
        ] {
            assert!(validate_body_fields(&[BodyField::new(pointer, "body")]).is_err());
        }
        assert!(
            validate_body_fields(&[valid
                .clone()
                .with_optional_owner_prefixes(vec!["/result/a".into()])])
            .is_err()
        );
        assert!(validate_body_fields(&[valid.clone().with_owner_equals(BTreeMap::new())]).is_err());
        assert!(validate_body_fields(&vec![valid; 65]).is_err());
        let mut null_predicate = serde_json::to_value(BodyField::new("/result", "body")).unwrap();
        null_predicate["ownerEquals"] = Value::Null;
        assert!(serde_json::from_value::<BodyField>(null_predicate).is_err());
        for key in [
            "ownerPath",
            "optionalOwnerPrefixes",
            "nullableOwnerPrefixes",
            "field",
            "optional",
            "nullable",
        ] {
            let mut field = serde_json::to_value(BodyField::new("/result", "body")).unwrap();
            field.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<BodyField>(field).is_err(), "{key}");
        }
    }
    #[test]
    fn source_selected_aggregate_and_final_bounds_fail_closed() {
        let resolved = resolve(ROOT, None, None);
        let mut result = json!({"body":"é🙂"});
        assert!(present_result(&resolved, &mut result, 5, 100).is_err());
        let expected = json!({"body":{"format":"markdown","value":"é🙂"}});
        let bytes = serde_json::to_vec(&expected).unwrap().len() as u64;
        let mut result = json!({"body":"é🙂"});
        present_result(&resolved, &mut result, 6, bytes).unwrap();
        assert_eq!(result, expected);
        let mut result = json!({"body":"é🙂"});
        assert!(present_result(&resolved, &mut result, 6, bytes - 1).is_err());
        const ITEMS: ActionPresentation = ActionPresentation::new(
            &[EmbeddedBody::new(
                &[BodyPathSegment::Field("items"), BodyPathSegment::Each],
                "body",
                &TextCodec,
            )],
            TEXT_FORMATS,
            OutputContentFormat::Text,
        );
        let mut result = json!({"items":[{"body":"first"},{"body":"second"}]});
        assert!(present_result(&resolve(ITEMS, None, None), &mut result, 100, 50).is_err());
    }
    #[test]
    fn invalid_declarations_and_codec_tag_mismatches_are_rejected() {
        assert!(
            ActionPresentation::new(&[], TEXT_FORMATS, OutputContentFormat::Text)
                .validate()
                .is_err()
        );
        assert!(
            ActionPresentation::new(
                ROOT.embedded_bodies(),
                TEXT_FORMATS,
                OutputContentFormat::Adf
            )
            .validate()
            .is_err()
        );
        assert!(
            ActionPresentation::new(
                ROOT.embedded_bodies(),
                OUTPUT_CONTENT_FORMATS,
                OutputContentFormat::Adf
            )
            .validate()
            .is_err()
        );
        const INVALID_WILDCARD: ActionPresentation = ActionPresentation::new(
            &[EmbeddedBody::new(
                &[BodyPathSegment::Field("*")],
                "body",
                &TextCodec,
            )],
            TEXT_FORMATS,
            OutputContentFormat::Text,
        );
        assert!(INVALID_WILDCARD.validate().is_err());
        struct Wrong;
        impl EmbeddedBodyCodec for Wrong {
            fn supported_formats(&self) -> &'static [OutputContentFormat] {
                TEXT_FORMATS
            }
            fn select(
                &self,
                _: &Value,
                _: OutputContentFormat,
                _: u64,
                _: &mut RenderBudget,
            ) -> Result<Option<SelectedContent>, RenderError> {
                Ok(Some(SelectedContent::text("wrong")))
            }
        }
        const WRONG: ActionPresentation = ActionPresentation::new(
            &[EmbeddedBody::new(&[], "body", &Wrong)],
            TEXT_FORMATS,
            OutputContentFormat::Markdown,
        );
        assert!(
            present_result(
                &resolve(WRONG, None, None),
                &mut json!({"body":"raw"}),
                100,
                1024
            )
            .is_err()
        );
    }
    #[test]
    fn absent_selected_sources_only_remove_optional_terminals() {
        struct Absent;
        impl EmbeddedBodyCodec for Absent {
            fn supported_formats(&self) -> &'static [OutputContentFormat] {
                TEXT_FORMATS
            }
            fn select(
                &self,
                _: &Value,
                _: OutputContentFormat,
                _: u64,
                _: &mut RenderBudget,
            ) -> Result<Option<SelectedContent>, RenderError> {
                Ok(None)
            }
        }
        const OPTIONAL: ActionPresentation = ActionPresentation::new(
            &[EmbeddedBody::new(&[], "body", &Absent).optional()],
            TEXT_FORMATS,
            OutputContentFormat::Markdown,
        );
        const REQUIRED: ActionPresentation = ActionPresentation::new(
            &[EmbeddedBody::new(&[], "body", &Absent)],
            TEXT_FORMATS,
            OutputContentFormat::Markdown,
        );
        let mut value = json!({"body":{},"id":1});
        present_result(&resolve(OPTIONAL, None, None), &mut value, 100, 1024).unwrap();
        assert_eq!(value, json!({"id":1}));
        assert!(
            present_result(
                &resolve(REQUIRED, None, None),
                &mut json!({"body":{}}),
                100,
                1024
            )
            .is_err()
        );
    }
}
