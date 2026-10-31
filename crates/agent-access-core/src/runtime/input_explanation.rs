//! Field-specific explanations of a native provider's `input_invalid` denial.
//!
//! Providers parse an action's inputs strictly and often deny malformed ones
//! with a generic message. On that failure path only, the host validates the
//! request's inputs against the action's published input schema. Only native
//! actions are explained: their schemas are written in Broker code and
//! tested against a diagnostic profile, while imported and command-backed
//! actions keep their adapter's message and their schemas are never
//! compiled or evaluated here (see `BrokerRuntime::explain_input_denial`).
//! When the
//! schema finds problems, the message names up to [`MAX_PROBLEMS`] of them,
//! for example `jira.comment.list inputs are invalid: inputs.maxResults must
//! be an integer`. When it finds none, the provider enforced a rule the schema
//! does not express, and its own message stands. Only the message changes: the
//! reason, decision, status, result and audit data are the provider's, so an
//! explanation never adds or removes a rejection.
//!
//! Messages reach responses, so they are built only from each problem's
//! location and kind and from schema constants: declared property names,
//! bounds, `enum` and `const` values and format names. They never contain a
//! supplied value or the validator's own messages, which quote values. A
//! supplied property name appears only when the schema declares it or it is
//! a plain identifier; any other key is shown as `<key>`.
//!
//! Explaining costs work the provider's own denial did not, so, as defence in
//! depth, it runs only within a [diagnostic budget](within_budget) checked
//! before the schema is compiled or any input validated.
use crate::imports::BoundedImportSchema;
use agent_access_provider::{Decision, ProviderError, ReasonCode};
use jsonschema::error::{TypeKind, ValidationErrorKind};
use jsonschema::paths::Location;
use jsonschema::{JsonType, ValidationError};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};

/// The most problems one message names.
const MAX_PROBLEMS: usize = 3;
/// The most validator errors read for one denial.
const MAX_ERRORS: usize = 32;
/// The most names or values one list shows.
const MAX_LISTED: usize = 12;
/// The most supplied property names one problem echoes.
const MAX_ECHOED: usize = 5;
/// The longest `const` value a message shows.
const MAX_CONSTANT_BYTES: usize = 64;
/// How a supplied key that may not be echoed is shown.
const HIDDEN_KEY: &str = "<key>";
const SEE_SCHEMA: &str = "see the action's input schema";

// The diagnostic budget. The validator has no deadline, and it collects the
// errors of every `anyOf` and `oneOf` branch eagerly, copying into each one
// the input value at its location. Without a bound, a schema with many
// failing branches and a large input multiply into gigabytes of copies before
// the first problem is read. An explanation therefore runs only when both
// factors are small: the input's size, and the errors the schema can yield
// for it, which `SchemaCost` bounds from the schema alone. The budget does
// not bound everything the validator does (it clones `const` and `enum`
// values into errors and evaluates `not`, `if` and `contains` subschemas in
// full), which is why only native schemas are explained and each must fit
// the diagnostic profile of `native_schemas_fit_the_diagnostic_profile`.
// Outside the budget the provider's own message stands.

/// The largest input explained, as an estimate of its in-memory size: 64
/// bytes for every JSON value plus its string and key bytes. An input
/// within it has at most 512 values.
const MAX_INPUT_FOOTPRINT: u64 = 32 * 1024;
const VALUE_FOOTPRINT: u64 = 64;
/// The most schema positions whose errors the validator copies input values
/// into. The values one position judges are disjoint, so its copies add up
/// to at most the input, and all copies to at most 256 × 32 KiB = 8 MiB.
/// The most expensive native schema has 92.
const MAX_COPIED_ERRORS: u64 = 256;
/// The most errors the validator may produce in all, copied or not, for an
/// input of the measured number of values. Each is a small record of its
/// location and kind, a few hundred bytes, so all fit in a few MiB. Native
/// schemas reach at most about 8,700 at 512 values.
const MAX_SCHEMA_ERRORS: u64 = 16 * 1024;

/// Whether `error` is a provider's own `input_invalid` denial, the only
/// failure an explanation may reword.
pub(super) fn is_input_denial(error: &ProviderError) -> bool {
    error.reason_code() == ReasonCode::InputInvalid
        && error.reason_code().host_port().is_none()
        && error.decision() == Decision::Deny
}

/// `error` with its message naming the problems `schema` finds in `inputs`,
/// or unchanged when it is not an input denial, explaining is outside the
/// diagnostic budget, the schema does not compile within the bounded local
/// profile, or the inputs satisfy it.
pub(super) fn explain(
    service: &str,
    action: &str,
    schema: &Value,
    inputs: &Value,
    mut error: ProviderError,
) -> ProviderError {
    if !is_input_denial(&error) {
        return error;
    }
    let problems = problems(schema, inputs);
    if problems.is_empty() {
        return error;
    }
    let shown = problems.len().min(MAX_PROBLEMS);
    let mut message = format!(
        "{service}.{action} inputs are invalid: {}",
        problems[..shown].join("; ")
    );
    if problems.len() > shown {
        message.push_str(&format!("; and {} more", problems.len() - shown));
    }
    error.message = message;
    error
}

/// The distinct problems `schema` finds in `inputs`, in the validator's
/// order; empty when explaining them is outside the diagnostic budget, the
/// schema does not compile or the inputs satisfy it.
fn problems(schema: &Value, inputs: &Value) -> Vec<String> {
    if !within_budget(schema, inputs) {
        return Vec::new();
    }
    let Ok(compiled) = BoundedImportSchema::compile(schema) else {
        return Vec::new();
    };
    let explainer = Explainer::new(schema, inputs);
    let mut problems = Vec::new();
    for error in compiled.validator().iter_errors(inputs).take(MAX_ERRORS) {
        explainer.describe(&error, &mut problems);
    }
    problems
}

/// Whether validating `inputs` against `schema` fits the diagnostic budget:
/// the input's footprint is at most [`MAX_INPUT_FOOTPRINT`], the schema has
/// at most [`MAX_COPIED_ERRORS`] copying positions, and it can yield at most
/// [`MAX_SCHEMA_ERRORS`] errors for an input of that many values. The input
/// measurement stops at the budget and the schema walks are linear in the
/// schema's size, so the check itself is bounded.
fn within_budget(schema: &Value, inputs: &Value) -> bool {
    let mut input = InputSize::default();
    if !input.fits(inputs) {
        return false;
    }
    let (Some(positions), Some(errors)) = (
        SchemaCost::of(schema, 1),
        SchemaCost::of(schema, input.values),
    ) else {
        return false;
    };
    positions.copied <= MAX_COPIED_ERRORS
        && errors.returned.saturating_add(errors.held) <= MAX_SCHEMA_ERRORS
}

/// The footprint and number of values of an input, measured until the
/// footprint passes [`MAX_INPUT_FOOTPRINT`].
#[derive(Default)]
struct InputSize {
    footprint: u64,
    values: u64,
}

impl InputSize {
    fn fits(&mut self, value: &Value) -> bool {
        self.values += 1;
        self.footprint = self.footprint.saturating_add(VALUE_FOOTPRINT);
        let fits = match value {
            Value::String(text) => self.add(text.len()),
            Value::Array(items) => items.iter().all(|item| self.fits(item)),
            Value::Object(members) => members
                .iter()
                .all(|(key, member)| self.add(key.len()) && self.fits(member)),
            Value::Null | Value::Bool(_) | Value::Number(_) => true,
        };
        fits && self.footprint <= MAX_INPUT_FOOTPRINT
    }

    fn add(&mut self, bytes: usize) -> bool {
        self.footprint = self.footprint.saturating_add(bytes as u64);
        self.footprint <= MAX_INPUT_FOOTPRINT
    }
}

/// Upper bounds on the errors validating one input can produce: those
/// returned at the top level, those held inside `anyOf` and `oneOf` errors,
/// and those the validator copies an input value into, which are the
/// errors of each branch it collects.
///
/// [`Self::of`] takes how many locations a schema applied to each member
/// can judge: the input's number of values, or 1 to count schema positions.
/// A keyword judges one location, except under `items`, `patternProperties`,
/// `additionalProperties` and the other keywords that apply a schema to
/// each member. Only `anyOf` and `oneOf` copy: `allOf`, `then`, `else` and
/// `properties` pass their errors on, and `if`, `not` and `contains` decide
/// without keeping any. A reference adds its target's cost wherever it is
/// used; a reference the walk cannot resolve within the document, or a
/// cycle, has no bound.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SchemaCost {
    returned: u64,
    held: u64,
    copied: u64,
}

impl SchemaCost {
    fn of(schema: &Value, each: u64) -> Option<Self> {
        CostWalk {
            root: schema,
            each,
            memo: HashMap::new(),
            active: HashSet::new(),
        }
        .cost(schema, 1)
    }

    fn add(&mut self, other: Self) {
        self.returned = self.returned.saturating_add(other.returned);
        self.held = self.held.saturating_add(other.held);
        self.copied = self.copied.saturating_add(other.copied);
    }

    /// One error at each of `locations`.
    fn error(&mut self, locations: u64) {
        self.returned = self.returned.saturating_add(locations);
    }
}

struct CostWalk<'a> {
    root: &'a Value,
    /// The locations a schema applied to each member can judge.
    each: u64,
    memo: HashMap<(&'a str, u64), SchemaCost>,
    active: HashSet<(&'a str, u64)>,
}

impl<'a> CostWalk<'a> {
    fn cost(&mut self, schema: &'a Value, locations: u64) -> Option<SchemaCost> {
        let mut cost = SchemaCost::default();
        let keywords = match schema {
            Value::Object(keywords) => keywords,
            Value::Bool(false) => {
                cost.error(locations);
                return Some(cost);
            }
            _ => return Some(cost),
        };
        let each = self.each;
        for (keyword, value) in keywords {
            match keyword.as_str() {
                "$schema" | "$id" | "$anchor" | "$dynamicAnchor" | "$recursiveAnchor"
                | "$vocabulary" | "$comment" | "$defs" | "definitions" | "title"
                | "description" | "default" | "examples" | "deprecated" | "readOnly"
                | "writeOnly" | "contentSchema" | "if" => {}
                keyword if keyword.starts_with("x-") => {}
                "required" => cost.error(locations.saturating_mul(array_len(value))),
                "dependentRequired" => {
                    for names in value.as_object().into_iter().flat_map(|map| map.values()) {
                        cost.error(locations.saturating_mul(array_len(names)));
                    }
                }
                "properties" | "dependentSchemas" => {
                    for member in value.as_object().into_iter().flat_map(|map| map.values()) {
                        cost.add(self.cost(member, locations)?);
                    }
                }
                "dependencies" => {
                    for member in value.as_object().into_iter().flat_map(|map| map.values()) {
                        match member {
                            Value::Array(names) => {
                                cost.error(locations.saturating_mul(names.len() as u64))
                            }
                            member => cost.add(self.cost(member, locations)?),
                        }
                    }
                }
                "patternProperties" => {
                    for member in value.as_object().into_iter().flat_map(|map| map.values()) {
                        cost.add(self.cost(member, each)?);
                    }
                }
                "prefixItems" => {
                    for item in value.as_array().into_iter().flatten() {
                        cost.add(self.cost(item, locations)?);
                    }
                }
                "items"
                | "additionalItems"
                | "additionalProperties"
                | "unevaluatedItems"
                | "unevaluatedProperties"
                | "propertyNames" => match value {
                    // `false` reports every unexpected member in one error.
                    Value::Bool(false) => cost.error(locations),
                    // A tuple of item schemas, each judging one location.
                    Value::Array(items) => {
                        for item in items {
                            cost.add(self.cost(item, locations)?);
                        }
                    }
                    value => cost.add(self.cost(value, each)?),
                },
                "allOf" | "then" | "else" => {
                    for member in members(value) {
                        cost.add(self.cost(member, locations)?);
                    }
                }
                "anyOf" | "oneOf" => {
                    cost.error(locations);
                    for branch in members(value) {
                        let branch = self.cost(branch, locations)?;
                        cost.held = cost
                            .held
                            .saturating_add(branch.returned)
                            .saturating_add(branch.held);
                        cost.copied = cost
                            .copied
                            .saturating_add(branch.returned)
                            .saturating_add(branch.copied);
                    }
                }
                "$ref" | "$dynamicRef" | "$recursiveRef" => {
                    cost.add(self.reference(value.as_str()?, locations)?);
                }
                _ => cost.error(locations),
            }
        }
        Some(cost)
    }

    /// The cost of the local schema `reference` points to.
    fn reference(&mut self, reference: &'a str, locations: u64) -> Option<SchemaCost> {
        let key = (reference, locations);
        if let Some(cost) = self.memo.get(&key) {
            return Some(*cost);
        }
        if !self.active.insert(key) {
            return None;
        }
        let pointer = reference.strip_prefix('#')?;
        let target = if pointer.is_empty() {
            self.root
        } else if pointer.starts_with('/') {
            self.root.pointer(&percent_decoded(pointer)?)?
        } else {
            return None;
        };
        let cost = self.cost(target, locations)?;
        self.active.remove(&key);
        self.memo.insert(key, cost);
        Some(cost)
    }
}

/// The subschemas of a keyword whose value is one schema or a list of them.
fn members(value: &Value) -> impl Iterator<Item = &Value> {
    match value {
        Value::Array(items) => items.iter().collect::<Vec<_>>(),
        value => vec![value],
    }
    .into_iter()
}

fn array_len(value: &Value) -> u64 {
    value.as_array().map_or(0, |items| items.len() as u64)
}

/// A URI fragment's JSON pointer with its percent escapes decoded; `None`
/// when an escape is malformed.
fn percent_decoded(pointer: &str) -> Option<String> {
    if !pointer.contains('%') {
        return Some(pointer.to_owned());
    }
    let bytes = pointer.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

struct Explainer<'a> {
    schema: &'a Value,
    inputs: &'a Value,
    /// Every property name the schema declares or requires anywhere.
    declared: BTreeSet<&'a str>,
}

impl<'a> Explainer<'a> {
    fn new(schema: &'a Value, inputs: &'a Value) -> Self {
        let mut declared = BTreeSet::new();
        declared_names(schema, &mut declared);
        Self {
            schema,
            inputs,
            declared,
        }
    }

    fn describe(&self, error: &ValidationError<'_>, out: &mut Vec<String>) {
        let at = self.path(error.instance_path());
        let problem = match error.kind() {
            ValidationErrorKind::AdditionalProperties { unexpected } => {
                self.unexpected(&at, unexpected, self.allowed(error.schema_path()))
            }
            ValidationErrorKind::UnevaluatedProperties { unexpected } => {
                self.unexpected(&at, unexpected, None)
            }
            ValidationErrorKind::Required { property } => match property.as_str() {
                Some(name) => format!("{at}.{name} is required"),
                None => format!("{at} is missing a required property"),
            },
            ValidationErrorKind::Type { kind } => format!("{at} must be {}", type_names(kind)),
            ValidationErrorKind::Enum { options } => match options.as_array() {
                Some(options) => format!(
                    "{at} must be one of: {}",
                    listed(options.iter().map(rendered))
                ),
                None => format!("{at} must be one of the documented values; {SEE_SCHEMA}"),
            },
            ValidationErrorKind::Constant { expected_value } => {
                let value = rendered(expected_value);
                if value.len() <= MAX_CONSTANT_BYTES {
                    format!("{at} must be {value}")
                } else {
                    format!("{at} must be the documented constant; {SEE_SCHEMA}")
                }
            }
            ValidationErrorKind::Minimum { limit } => format!("{at} must be at least {limit}"),
            ValidationErrorKind::ExclusiveMinimum { limit } => {
                format!("{at} must be greater than {limit}")
            }
            ValidationErrorKind::Maximum { limit } => format!("{at} must be at most {limit}"),
            ValidationErrorKind::ExclusiveMaximum { limit } => {
                format!("{at} must be less than {limit}")
            }
            ValidationErrorKind::MultipleOf { multiple_of } => {
                format!("{at} must be a multiple of {multiple_of}")
            }
            ValidationErrorKind::MinLength { limit } => format!(
                "{at} must be at least {limit} {} long",
                plural(*limit, "character", "characters")
            ),
            ValidationErrorKind::MaxLength { limit } => format!(
                "{at} must be at most {limit} {} long",
                plural(*limit, "character", "characters")
            ),
            ValidationErrorKind::MinItems { limit } => format!(
                "{at} must contain at least {limit} {}",
                plural(*limit, "item", "items")
            ),
            ValidationErrorKind::MaxItems { limit } => format!(
                "{at} must contain at most {limit} {}",
                plural(*limit, "item", "items")
            ),
            ValidationErrorKind::AdditionalItems { limit } => format!(
                "{at} must contain at most {limit} {}",
                plural(*limit as u64, "item", "items")
            ),
            ValidationErrorKind::MinProperties { limit } => format!(
                "{at} must contain at least {limit} {}",
                plural(*limit, "property", "properties")
            ),
            ValidationErrorKind::MaxProperties { limit } => format!(
                "{at} must contain at most {limit} {}",
                plural(*limit, "property", "properties")
            ),
            ValidationErrorKind::UniqueItems => format!("{at} must not contain duplicate items"),
            ValidationErrorKind::Contains => {
                format!("{at} must contain an item of the documented form; {SEE_SCHEMA}")
            }
            ValidationErrorKind::UnevaluatedItems { .. } => {
                format!("{at} contains items that are not allowed")
            }
            ValidationErrorKind::Pattern { .. }
            | ValidationErrorKind::BacktrackLimitExceeded { .. }
            | ValidationErrorKind::RegexEngineFailure { .. } => {
                format!("{at} does not match the required format")
            }
            ValidationErrorKind::Format { format } => format!("{at} must be a valid {format}"),
            ValidationErrorKind::ContentEncoding { content_encoding } => {
                format!("{at} must be {content_encoding}-encoded")
            }
            ValidationErrorKind::FromUtf8 { .. } => format!("{at} must decode to UTF-8 text"),
            ValidationErrorKind::ContentMediaType { content_media_type } => {
                format!("{at} must be {content_media_type} content")
            }
            ValidationErrorKind::PropertyNames { .. } => {
                format!("{at} has a property name that is not allowed")
            }
            ValidationErrorKind::FalseSchema => self.refused(&at, error),
            ValidationErrorKind::Not { schema } => self.forbidden(&at, schema),
            ValidationErrorKind::AnyOf { context }
            | ValidationErrorKind::OneOfNotValid { context } => {
                return self.alternatives(error.instance_path(), &at, context, out);
            }
            ValidationErrorKind::OneOfMultipleValid { .. } => self.ambiguous(&at, error),
            // A reference the schema cannot resolve says nothing about the inputs.
            ValidationErrorKind::Referencing(_) => return,
            _ => format!("{at} is invalid; {SEE_SCHEMA}"),
        };
        push(out, problem);
    }

    /// The `oneOf` or `anyOf` problem at `location`: the problems of the one
    /// form that applies to the inputs, the properties every remaining form
    /// requires, or the types they accept; otherwise a pointer to the schema.
    fn alternatives(
        &self,
        location: &Location,
        at: &str,
        forms: &[Vec<ValidationError<'static>>],
        out: &mut Vec<String>,
    ) {
        let here = location.as_str();
        // A form that forbids something supplied (`not`) explains less than
        // one the inputs only partly satisfy.
        let mut candidates: Vec<&[ValidationError<'static>]> = forms
            .iter()
            .map(Vec::as_slice)
            .filter(|errors| {
                !errors
                    .iter()
                    .any(|error| matches!(error.kind(), ValidationErrorKind::Not { .. }))
            })
            .collect();
        if candidates.is_empty() {
            candidates = forms.iter().map(Vec::as_slice).collect();
        }
        // A form whose discriminating constant below this location the
        // inputs do not match does not apply to them.
        let applicable: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|errors| {
                !errors.iter().any(|error| {
                    matches!(error.kind(), ValidationErrorKind::Constant { .. })
                        && is_below(error.instance_path().as_str(), here)
                })
            })
            .collect();
        if !applicable.is_empty() {
            candidates = applicable;
        }
        if let [form] = candidates.as_slice() {
            for error in *form {
                self.describe(error, out);
            }
            return;
        }
        if let Some(sets) = required_sets(&candidates, here) {
            if let [names] = sets.as_slice() {
                for name in names {
                    push(out, format!("{at}.{name} is required"));
                }
            } else {
                let sets: Vec<String> = sets.iter().map(|names| all_of(names)).collect();
                push(out, format!("{at} must include {}", either(&sets)));
            }
            return;
        }
        if let Some(types) = accepted_types(&candidates, here) {
            push(out, format!("{at} must be {}", either(&types)));
            return;
        }
        push(
            out,
            format!("{at} must match one of the documented forms; {SEE_SCHEMA}"),
        );
    }

    /// The problem of inputs that satisfy several `oneOf` forms, naming them
    /// when each form is one required property.
    fn ambiguous(&self, at: &str, error: &ValidationError<'_>) -> String {
        let names: Option<Vec<&str>> = self
            .schema
            .pointer(error.schema_path().as_str())
            .and_then(Value::as_array)
            .and_then(|forms| {
                forms
                    .iter()
                    .map(|form| match required_only(form).as_deref() {
                        Some([name]) => Some(*name),
                        _ => None,
                    })
                    .collect()
            });
        match names {
            Some(names) if names.len() > 1 => {
                format!("{at} must include only one of: {}", listed(names))
            }
            _ => format!("{at} matches more than one documented form; {SEE_SCHEMA}"),
        }
    }

    /// The problem of inputs a `not` schema forbids, naming the properties
    /// when it forbids a set of them.
    fn forbidden(&self, at: &str, schema: &Value) -> String {
        match required_only(schema).as_deref() {
            Some([name]) => format!("{at}.{name} is not allowed with these inputs"),
            Some(names) if names.len() > 1 => format!("{at} must not include {}", all_of(names)),
            _ => format!("{at} combines inputs in a way the action does not allow; {SEE_SCHEMA}"),
        }
    }

    /// A value a `false` schema refuses. `additionalProperties: false` on an
    /// object that declares no properties refuses the whole object, so its
    /// supplied properties are reported as unexpected ones.
    fn refused(&self, at: &str, error: &ValidationError<'_>) -> String {
        let keyword = error.schema_path();
        if keyword.as_str().ends_with("/additionalProperties")
            && let Some(Value::Object(supplied)) =
                self.inputs.pointer(error.instance_path().as_str())
        {
            let declared = keyword
                .as_str()
                .strip_suffix("/additionalProperties")
                .and_then(|parent| self.schema.pointer(parent))
                .and_then(|node| node.get("properties"))
                .and_then(Value::as_object);
            let unexpected: Vec<String> = supplied
                .keys()
                .filter(|name| declared.is_none_or(|declared| !declared.contains_key(*name)))
                .cloned()
                .collect();
            if !unexpected.is_empty() {
                return self.unexpected(at, &unexpected, self.allowed(keyword));
            }
        }
        format!("{at} is not allowed")
    }

    /// Unexpected properties at `at`, echoing only names it may show.
    fn unexpected(&self, at: &str, unexpected: &[String], allowed: Option<String>) -> String {
        let mut named = Vec::new();
        let mut others = 0usize;
        for name in unexpected {
            if named.len() < MAX_ECHOED && self.displayable(name) {
                named.push(format!("{at}.{name}"));
            } else {
                others += 1;
            }
        }
        let mut problem = match (named.as_slice(), others) {
            ([], 1) => format!("an unexpected property in {at} is not allowed"),
            ([], count) => format!("{count} unexpected properties in {at} are not allowed"),
            ([name], 0) => format!("{name} is not allowed"),
            (names, 0) => format!("{} are not allowed", and_list(names)),
            (names, count) => format!(
                "{} and {count} other unexpected {} are not allowed",
                names.join(", "),
                plural(count as u64, "property", "properties")
            ),
        };
        if let Some(allowed) = allowed {
            problem.push_str("; allowed: ");
            problem.push_str(&allowed);
        }
        problem
    }

    /// The properties the object whose `additionalProperties` keyword is at
    /// `keyword` declares; none when it also admits patterns.
    fn allowed(&self, keyword: &Location) -> Option<String> {
        let parent = keyword.as_str().strip_suffix("/additionalProperties")?;
        let node = self.schema.pointer(parent)?;
        if node.get("patternProperties").is_some() {
            return None;
        }
        Some(match node.get("properties").and_then(Value::as_object) {
            Some(properties) if !properties.is_empty() => {
                listed(properties.keys().map(String::as_str))
            }
            _ => "none".to_owned(),
        })
    }

    /// `inputs` followed by the dotted or indexed segments of `location`,
    /// with a key it may not show replaced by [`HIDDEN_KEY`].
    fn path(&self, location: &Location) -> String {
        let mut path = String::from("inputs");
        let mut node = Some(self.inputs);
        for raw in location.as_str().split('/').skip(1) {
            let segment = raw.replace("~1", "/").replace("~0", "~");
            match node {
                Some(Value::Array(items)) => match segment.parse::<usize>() {
                    Ok(index) => {
                        path.push_str(&format!("[{index}]"));
                        node = items.get(index);
                    }
                    Err(_) => {
                        path.push_str("[]");
                        node = None;
                    }
                },
                _ => {
                    path.push('.');
                    path.push_str(if self.displayable(&segment) {
                        &segment
                    } else {
                        HIDDEN_KEY
                    });
                    node = node.and_then(|node| node.get(&segment));
                }
            }
        }
        path
    }

    /// Whether a supplied property name may appear in a message: the schema
    /// declares it, or it is a plain identifier.
    fn displayable(&self, name: &str) -> bool {
        self.declared.contains(name) || is_identifier(name)
    }
}

/// `^[A-Za-z][A-Za-z0-9_]{0,63}$`.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 64
        && chars
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic())
        && chars.all(|rest| rest.is_ascii_alphanumeric() || rest == '_')
}

/// Collects the names under every `properties` and `required` keyword of
/// `schema`, without descending into data keywords.
fn declared_names<'a>(schema: &'a Value, names: &mut BTreeSet<&'a str>) {
    match schema {
        Value::Object(keywords) => {
            for (keyword, value) in keywords {
                match keyword.as_str() {
                    "enum" | "const" | "default" | "examples" => continue,
                    "properties" => {
                        if let Some(properties) = value.as_object() {
                            names.extend(properties.keys().map(String::as_str));
                        }
                    }
                    "required" => {
                        if let Some(required) = value.as_array() {
                            names.extend(required.iter().filter_map(Value::as_str));
                        }
                    }
                    _ => {}
                }
                declared_names(value, names);
            }
        }
        Value::Array(items) => {
            for item in items {
                declared_names(item, names);
            }
        }
        _ => {}
    }
}

/// The names of a schema that only requires properties, such as the forms
/// of `oneOf: [{required: [issue]}, {required: [url]}]`.
fn required_only(schema: &Value) -> Option<Vec<&str>> {
    let keywords = schema.as_object()?;
    if keywords.len() != 1 {
        return None;
    }
    let names: Vec<&str> = keywords
        .get("required")?
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect::<Option<_>>()?;
    (!names.is_empty()).then_some(names)
}

/// The distinct sets of properties each form is missing at `here`, when
/// missing properties are each form's only problems.
fn required_sets<'e>(
    forms: &[&'e [ValidationError<'static>]],
    here: &str,
) -> Option<Vec<Vec<&'e str>>> {
    let mut sets: Vec<Vec<&str>> = Vec::new();
    for form in forms {
        if form.is_empty() {
            return None;
        }
        let names = form
            .iter()
            .map(|error| match error.kind() {
                ValidationErrorKind::Required { property }
                    if error.instance_path().as_str() == here =>
                {
                    property.as_str()
                }
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        if !sets.contains(&names) {
            sets.push(names);
        }
    }
    Some(sets)
}

/// The types the forms accept at `here`, when each form's only problem is
/// a type mismatch there.
fn accepted_types(forms: &[&[ValidationError<'static>]], here: &str) -> Option<Vec<String>> {
    let mut types = Vec::new();
    for form in forms {
        let [error] = form else {
            return None;
        };
        match error.kind() {
            ValidationErrorKind::Type { kind } if error.instance_path().as_str() == here => {
                types.extend(json_types(kind));
            }
            _ => return None,
        }
    }
    Some(ordered_type_names(types))
}

fn json_types(kind: &TypeKind) -> Vec<JsonType> {
    match kind {
        TypeKind::Single(json_type) => vec![*json_type],
        TypeKind::Multiple(types) => types.iter().collect(),
    }
}

fn type_names(kind: &TypeKind) -> String {
    either(&ordered_type_names(json_types(kind)))
}

/// Distinct type names with an article, in order with `null` last.
fn ordered_type_names(types: Vec<JsonType>) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for json_type in types
        .iter()
        .filter(|json_type| **json_type != JsonType::Null)
        .chain(
            types
                .iter()
                .filter(|json_type| **json_type == JsonType::Null),
        )
    {
        let name = type_name(*json_type).to_owned();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

fn type_name(json_type: JsonType) -> &'static str {
    match json_type {
        JsonType::Array => "an array",
        JsonType::Boolean => "a boolean",
        JsonType::Integer => "an integer",
        JsonType::Null => "null",
        JsonType::Number => "a number",
        JsonType::Object => "an object",
        JsonType::String => "a string",
    }
}

/// A schema constant as a message shows it: a plain string as itself, any
/// other value as compact JSON.
fn rendered(value: &Value) -> String {
    match value.as_str() {
        Some(text)
            if !text.is_empty()
                && !text
                    .chars()
                    .any(|c| c == ',' || c == ';' || c.is_whitespace() || c.is_control()) =>
        {
            text.to_owned()
        }
        _ => value.to_string(),
    }
}

/// At most [`MAX_LISTED`] items joined by commas, then how many remain.
fn listed<T: AsRef<str>>(items: impl IntoIterator<Item = T>) -> String {
    let items: Vec<T> = items.into_iter().collect();
    let shown: Vec<&str> = items.iter().take(MAX_LISTED).map(AsRef::as_ref).collect();
    let mut list = shown.join(", ");
    if items.len() > shown.len() {
        list.push_str(&format!(", and {} more", items.len() - shown.len()));
    }
    list
}

/// `a`, `both a and b`, or `all of a, b and c`.
fn all_of(names: &[&str]) -> String {
    match names {
        [name] => (*name).to_owned(),
        [first, second] => format!("both {first} and {second}"),
        names => format!("all of {}", and_list(names)),
    }
}

/// `a`, `a and b`, or `a, b and c`.
fn and_list<T: AsRef<str>>(items: &[T]) -> String {
    joined(items, "and")
}

/// `a`, `a or b`, or `a, b or c`.
fn either<T: AsRef<str>>(items: &[T]) -> String {
    joined(items, "or")
}

fn joined<T: AsRef<str>>(items: &[T], conjunction: &str) -> String {
    match items {
        [] => String::new(),
        [only] => only.as_ref().to_owned(),
        [init @ .., last] => format!(
            "{} {conjunction} {}",
            init.iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .join(", "),
            last.as_ref()
        ),
    }
}

fn plural(count: u64, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 { one } else { many }
}

/// Whether `path` is strictly below `here`.
fn is_below(path: &str, here: &str) -> bool {
    path.strip_prefix(here)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn push(out: &mut Vec<String>, problem: String) {
    if !out.contains(&problem) {
        out.push(problem);
    }
}

#[cfg(test)]
#[path = "input_explanation_tests.rs"]
mod tests;
