//! Result schemas: the JSON Schemas of an action's provider payloads, which
//! the host composes into advertised MCP output schemas, catalog entries and
//! typed OpenAPI responses.
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// The largest compact JSON size of one action's success and error schemas
/// together, after bundle references are inlined.
pub(crate) const RESULT_SCHEMAS_MAX_BYTES: usize = 8192;

/// The provider payload schemas of one action: the success `result` and,
/// when the action reports result-bearing failures, a provider error
/// `result`. Attach them with
/// [`ActionDescriptor::result_schemas`](crate::ActionDescriptor::result_schemas).
///
/// ```
/// use agent_access_provider::ActionResultSchemas;
/// use serde_json::json;
///
/// let schemas = ActionResultSchemas::new(json!({
///     "type": "object",
///     "properties": {"id": {"type": "string"}},
///     "required": ["id"]
/// }))
/// .with_error(json!({"type": "object", "properties": {"conflict": {"type": "boolean"}}}));
/// assert_eq!(schemas.success()["required"], json!(["id"]));
/// assert!(schemas.error().is_some());
/// ```
///
/// The schemas describe the provider's final JSON payload before
/// presentation and before the Broker envelope: what
/// [`Provider::invoke`](crate::Provider::invoke) returns as the success
/// `result` (a raw download's metadata `result`), and what a provider error
/// carries as `result`. They never describe upstream API models, MCP wrappers
/// or the whole-result Markdown text, which the host adds itself. Native
/// providers author them in bundled JSON beside their action documentation
/// and load them once through a static [`ResultSchemaBundle`].
///
/// # Authoring profile
///
/// Published schemas use a portable subset that validates the same way in
/// draft-07 and 2020-12 validators.
/// [`ServiceDescriptor::validate`](crate::ServiceDescriptor::validate)
/// rejects anything else:
///
/// - allowed keywords: `type` (a name or an array of names), `properties`,
///   `required` (names `properties` declares), `additionalProperties`
///   (Boolean or schema), `items` (one schema), `enum`, `const`, `anyOf`,
///   `minimum`, `maximum`, `minItems`, `maxItems`, `minLength`, `maxLength`
///   and `description`;
/// - both roots are `{"type": "object", ...}`;
/// - the compact JSON of both schemas together is at most 8,192 bytes;
/// - every rendered-body owner of the action's presentation resolves in the
///   success schema; the host adds the optional `renderedBody` there, and in
///   the error schema wherever the owner path resolves.
///
/// Leave objects open (omit `additionalProperties`); declare explicit maps
/// with `additionalProperties: <schema>`. Genuinely opaque upstream JSON is an
/// explicit open leaf, `{}` or `{"type": "object"}` without `properties`.
/// Mark fields `required` only when the projection always emits them.
/// Schemas are supersets across every supported configuration and input.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct ActionResultSchemas {
    success: Value,
    error: Option<Value>,
}

impl ActionResultSchemas {
    /// The schema of the action's success `result`.
    pub fn new(success: Value) -> Self {
        Self {
            success,
            error: None,
        }
    }

    /// Adds the schema of the `result` the action's provider errors carry,
    /// without the shared receipt, retry and execution fields the host
    /// merges in.
    pub fn with_error(mut self, error: Value) -> Self {
        self.error = Some(error);
        self
    }

    pub fn success(&self) -> &Value {
        &self.success
    }

    pub fn error(&self) -> Option<&Value> {
        self.error.as_ref()
    }
}

/// Bundled result schemas, parsed once on first use. Declare one as a
/// `static` over the provider's bundle files and read each action's schemas
/// with [`Self::action`].
///
/// Each file is a JSON object with an `actions` map and optional
/// `definitions`. Every action entry has a `success` schema and an optional
/// `error` schema. A `{"$ref": "#/definitions/<name>"}` node, optionally with a
/// sibling `description`, is replaced by that file's definition; references
/// resolve in their own file only, and a recursive reference is an authoring
/// error. Several files declare disjoint actions.
///
/// ```
/// use agent_access_provider::ResultSchemaBundle;
///
/// static RESULT_SCHEMAS: ResultSchemaBundle = ResultSchemaBundle::new(&[r##"{
///     "definitions": {"key": {"type": "string", "description": "Item key."}},
///     "actions": {
///         "item.view": {
///             "success": {
///                 "type": "object",
///                 "properties": {"key": {"$ref": "#/definitions/key"}},
///                 "required": ["key"]
///             }
///         }
///     }
/// }"##]);
///
/// let schemas = RESULT_SCHEMAS.action("item.view");
/// assert_eq!(schemas.success()["properties"]["key"]["type"], "string");
/// assert_eq!(RESULT_SCHEMAS.actions(), ["item.view"]);
/// ```
#[non_exhaustive]
pub struct ResultSchemaBundle {
    sources: &'static [&'static str],
    parsed: OnceLock<BTreeMap<String, ActionResultSchemas>>,
}

impl ResultSchemaBundle {
    /// A bundle of the JSON files `sources`, usually `include_str!` of each.
    pub const fn new(sources: &'static [&'static str]) -> Self {
        Self {
            sources,
            parsed: OnceLock::new(),
        }
    }

    fn parsed(&self) -> &BTreeMap<String, ActionResultSchemas> {
        self.parsed.get_or_init(|| {
            parse_bundle_sources(self.sources)
                .unwrap_or_else(|error| panic!("invalid bundled result schemas: {error}"))
        })
    }

    /// The schemas of `action`.
    ///
    /// # Panics
    ///
    /// When the bundle is malformed or declares no entry for `action`: a
    /// bundled asset is part of the provider's source.
    pub fn action(&self, action: &str) -> ActionResultSchemas {
        self.parsed()
            .get(action)
            .cloned()
            .unwrap_or_else(|| panic!("bundled result schemas declare no entry for {action}"))
    }

    /// Every action the bundle declares, in sorted order, so a provider test
    /// can require an entry for each published action and no other.
    ///
    /// # Panics
    ///
    /// When the bundle is malformed.
    pub fn actions(&self) -> Vec<&str> {
        self.parsed().keys().map(String::as_str).collect()
    }
}

impl std::fmt::Debug for ResultSchemaBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResultSchemaBundle")
            .field("sources", &self.sources.len())
            .finish_non_exhaustive()
    }
}

fn parse_bundle_sources(sources: &[&str]) -> Result<BTreeMap<String, ActionResultSchemas>, String> {
    let mut actions = BTreeMap::new();
    for (index, source) in sources.iter().enumerate() {
        let file = |error: String| format!("file {index}: {error}");
        let bundle: Value =
            serde_json::from_str(source).map_err(|error| file(format!("invalid JSON: {error}")))?;
        let bundle = bundle
            .as_object()
            .ok_or_else(|| file("must be a JSON object".into()))?;
        if let Some(key) = bundle
            .keys()
            .find(|key| !matches!(key.as_str(), "actions" | "definitions"))
        {
            return Err(file(format!("unsupported top-level key {key}")));
        }
        let empty = Map::new();
        let definitions = match bundle.get("definitions") {
            None => &empty,
            Some(Value::Object(definitions)) => definitions,
            Some(_) => return Err(file("definitions must be an object".into())),
        };
        let entries = bundle
            .get("actions")
            .and_then(Value::as_object)
            .ok_or_else(|| file("needs an actions object".into()))?;
        for (action, entry) in entries {
            let entry = entry
                .as_object()
                .ok_or_else(|| file(format!("action {action} must be an object")))?;
            if let Some(key) = entry
                .keys()
                .find(|key| !matches!(key.as_str(), "success" | "error"))
            {
                return Err(file(format!("action {action} has unsupported key {key}")));
            }
            let inline = |schema: &Value, kind: &str| {
                inline_definitions(schema, definitions, &mut Vec::new())
                    .map_err(|error| file(format!("action {action} {kind} schema: {error}")))
            };
            let success = entry
                .get("success")
                .ok_or_else(|| file(format!("action {action} needs a success schema")))?;
            let mut schemas = ActionResultSchemas::new(inline(success, "success")?);
            if let Some(error) = entry.get("error") {
                schemas = schemas.with_error(inline(error, "error")?);
            }
            if actions.insert(action.clone(), schemas).is_some() {
                return Err(format!("action {action} is declared in more than one file"));
            }
        }
    }
    Ok(actions)
}

/// `schema` with every `#/definitions/<name>` reference replaced by its
/// definition. Only schema-valued keywords are walked; anything else is
/// copied unchanged for the profile check to judge.
fn inline_definitions(
    schema: &Value,
    definitions: &Map<String, Value>,
    stack: &mut Vec<String>,
) -> Result<Value, String> {
    let Value::Object(object) = schema else {
        return Ok(schema.clone());
    };
    if let Some(reference) = object.get("$ref") {
        let name = reference
            .as_str()
            .and_then(|reference| reference.strip_prefix("#/definitions/"))
            .filter(|name| !name.is_empty() && !name.contains('/'))
            .map(|name| name.replace("~1", "/").replace("~0", "~"))
            .ok_or_else(|| "references must name #/definitions/<name>".to_string())?;
        if let Some(key) = object
            .keys()
            .find(|key| !matches!(key.as_str(), "$ref" | "description"))
        {
            return Err(format!("reference to {name} has unsupported sibling {key}"));
        }
        if stack.contains(&name) {
            return Err(format!("definition {name} refers to itself"));
        }
        let definition = definitions
            .get(&name)
            .ok_or_else(|| format!("definition {name} does not exist"))?;
        stack.push(name);
        let mut inlined = inline_definitions(definition, definitions, stack)?;
        stack.pop();
        if let (Some(description), Some(target)) =
            (object.get("description"), inlined.as_object_mut())
        {
            target.insert("description".into(), description.clone());
        }
        return Ok(inlined);
    }
    let mut result = Map::new();
    for (key, value) in object {
        let value = match (key.as_str(), value) {
            ("properties", Value::Object(properties)) => Value::Object(
                properties
                    .iter()
                    .map(|(name, property)| {
                        inline_definitions(property, definitions, stack)
                            .map(|property| (name.clone(), property))
                    })
                    .collect::<Result<_, _>>()?,
            ),
            ("anyOf", Value::Array(branches)) => Value::Array(
                branches
                    .iter()
                    .map(|branch| inline_definitions(branch, definitions, stack))
                    .collect::<Result<_, _>>()?,
            ),
            ("items" | "additionalProperties", value @ Value::Object(_)) => {
                inline_definitions(value, definitions, stack)?
            }
            _ => value.clone(),
        };
        result.insert(key.clone(), value);
    }
    Ok(Value::Object(result))
}

const PROFILE_KEYWORDS: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "anyOf",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
    "minLength",
    "maxLength",
    "description",
];
const JSON_TYPES: &[&str] = &[
    "object", "array", "string", "number", "integer", "boolean", "null",
];

/// The authoring-profile problems of `schema` at the JSON pointer `path`.
fn profile_problems(schema: &Value, path: &str, problems: &mut Vec<String>) {
    let at = |path: &str| if path.is_empty() { "root" } else { path }.to_string();
    let Value::Object(object) = schema else {
        problems.push(format!("{} must be a schema object", at(path)));
        return;
    };
    for (key, value) in object {
        let child = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
        match key.as_str() {
            "type" => {
                let names = match value {
                    Value::String(name) => vec![Some(name.as_str())],
                    Value::Array(names) if !names.is_empty() => {
                        names.iter().map(Value::as_str).collect()
                    }
                    _ => vec![None],
                };
                let mut seen = BTreeSet::new();
                if names.iter().any(|name| {
                    name.is_none_or(|name| !JSON_TYPES.contains(&name) || !seen.insert(name))
                }) {
                    problems.push(format!("{} must name distinct JSON types", at(&child)));
                }
            }
            "properties" => match value {
                Value::Object(properties) => {
                    for (name, property) in properties {
                        profile_problems(
                            property,
                            &format!("{child}/{}", name.replace('~', "~0").replace('/', "~1")),
                            problems,
                        );
                    }
                }
                _ => problems.push(format!("{} must be an object", at(&child))),
            },
            "required" => {
                let declared = object.get("properties").and_then(Value::as_object);
                let valid = value.as_array().is_some_and(|names| {
                    let mut seen = BTreeSet::new();
                    names.iter().all(|name| {
                        name.as_str().is_some_and(|name| {
                            seen.insert(name)
                                && declared.is_some_and(|declared| declared.contains_key(name))
                        })
                    })
                });
                if !valid {
                    problems.push(format!(
                        "{} must list distinct names its properties declare",
                        at(&child)
                    ));
                }
            }
            "additionalProperties" => {
                if !value.is_boolean() {
                    profile_problems(value, &child, problems);
                }
            }
            "items" => profile_problems(value, &child, problems),
            "anyOf" => match value.as_array() {
                Some(branches) if !branches.is_empty() => {
                    for (index, branch) in branches.iter().enumerate() {
                        profile_problems(branch, &format!("{child}/{index}"), problems);
                    }
                }
                _ => problems.push(format!("{} must be a non-empty array", at(&child))),
            },
            "enum" => {
                if !value.as_array().is_some_and(|values| !values.is_empty()) {
                    problems.push(format!("{} must be a non-empty array", at(&child)));
                }
            }
            "const" => {}
            "minimum" | "maximum" => {
                if !value.is_number() {
                    problems.push(format!("{} must be a number", at(&child)));
                }
            }
            "minItems" | "maxItems" | "minLength" | "maxLength" => {
                if value.as_u64().is_none() {
                    problems.push(format!("{} must be a non-negative integer", at(&child)));
                }
            }
            "description" => {
                if !value.is_string() {
                    problems.push(format!("{} must be a string", at(&child)));
                }
            }
            _ => {
                debug_assert!(!PROFILE_KEYWORDS.contains(&key.as_str()));
                problems.push(format!(
                    "{} uses keyword {key} outside the result schema profile",
                    at(path)
                ));
            }
        }
    }
}

/// The descriptor-validation errors of one action's result schemas.
pub(crate) fn validate_action_result_schemas(
    label: &str,
    schemas: &ActionResultSchemas,
    owner_pointers: &[String],
    errors: &mut Vec<String>,
) {
    let mut size = 0;
    for (kind, schema) in [
        ("success", Some(&schemas.success)),
        ("error", schemas.error.as_ref()),
    ] {
        let Some(schema) = schema else {
            continue;
        };
        size += serde_json::to_vec(schema).map_or(usize::MAX, |bytes| bytes.len());
        let mut problems = Vec::new();
        profile_problems(schema, "", &mut problems);
        if schema.get("type").and_then(Value::as_str) != Some("object") {
            problems.push("root must describe an object".into());
        }
        for problem in &problems {
            errors.push(format!("{label} {kind} result schema: {problem}"));
        }
        if problems.is_empty()
            && let Err(error) = jsonschema::validator_for(schema)
        {
            errors.push(format!("{label} {kind} result schema is invalid: {error}"));
        }
    }
    if size > RESULT_SCHEMAS_MAX_BYTES {
        errors.push(format!(
            "{label} result schemas exceed {RESULT_SCHEMAS_MAX_BYTES} bytes"
        ));
    }
    let mut success = schemas.success.clone();
    for pointer in owner_pointers {
        if crate::presentation::inject_rendered_body_schema(&mut success, pointer).is_err() {
            errors.push(format!(
                "{label} success result schema does not resolve rendered body owner {}",
                if pointer.is_empty() { "/" } else { pointer }
            ));
        }
    }
}

/// The shared `result` of a failed or refused request: the retry, receipt and
/// execution details the SDK's helpers, the Broker host and its admission
/// add, whatever the action. Every property is optional and the object is
/// open, so a validator accepts fields a later Broker adds.
///
/// The host merges these properties into each provider error schema (see
/// [`with_shared_failure_properties`]) and offers this schema as the failure
/// branch of every action's composed result.
pub fn shared_failure_result_schema() -> Value {
    json!({
        "type": "object",
        "description": "Retry, receipt or execution details for a failed or refused request.",
        "properties": shared_failure_properties(),
    })
}

fn shared_failure_properties() -> Value {
    let integer = json!({"type": "integer"});
    json!({
        "mutationStatus": {
            "type": "string",
            "enum": ["not_applied", "unknown", "applied_unverified", "applied", "applied_verified"],
            "description": "Whether the write applied; only not_applied is safe to retry."
        },
        "retrySafe": {"type": "boolean", "description": "Whether repeating the request cannot apply anything twice."},
        "verificationStage": {"type": "string", "description": "The check that could not confirm an applied write."},
        "safeLocators": {"type": "object", "description": "Provider-defined identifiers of what changed, for reconciliation."},
        "operationDispatched": {"type": "boolean", "description": "Whether a command import started its process."},
        "executionState": {"type": "string", "enum": ["not_dispatched", "unknown", "completed"]},
        "deadlineKind": {"type": "string", "enum": ["rate_wait", "operation", "body"]},
        "limitScope": {"type": "string", "enum": ["upstream", "principal", "service"]},
        "service": {"type": "string"},
        "limit": integer,
        "windowSeconds": integer,
        "retryAfterSeconds": {"type": "integer", "description": "Seconds to wait before retrying."},
        "retryAt": {"type": "string", "description": "RFC 3339 instant after which a retry may succeed."},
        "maxWaitSeconds": integer,
        "queuedRequests": integer,
        "waitedMilliseconds": integer,
        "remainingWaitMilliseconds": integer,
        "hints": {
            "type": "object",
            "properties": {"upstreamResourceOwnership": {"type": "string", "enum": ["acting_user"]}}
        }
    })
}

/// `error` with every shared failure property it does not declare itself
/// added to its `properties` and to those of each object branch of a root
/// `anyOf`, so one branch validates a provider error that also carries a
/// receipt or retry details. The provider's own declarations win. The merged
/// copies omit descriptions, which the shared failure schema carries.
pub fn with_shared_failure_properties(error: &Value) -> Value {
    let mut error = error.clone();
    let mut shared = shared_failure_properties();
    let shared = shared.as_object_mut().expect("shared failure properties");
    for property in shared.values_mut().filter_map(Value::as_object_mut) {
        property.remove("description");
    }
    let shared = &*shared;
    let merge = |schema: &mut Map<String, Value>| {
        let properties = schema
            .entry("properties")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(properties) = properties.as_object_mut() {
            for (name, property) in shared {
                properties
                    .entry(name.clone())
                    .or_insert_with(|| property.clone());
            }
        }
    };
    if let Some(object) = error.as_object_mut() {
        if let Some(Value::Array(branches)) = object.get_mut("anyOf") {
            for branch in branches.iter_mut().filter_map(Value::as_object_mut) {
                if branch.contains_key("properties")
                    || branch.get("type").and_then(Value::as_str) == Some("object")
                {
                    merge(branch);
                }
            }
        }
        if object.contains_key("properties") || !object.contains_key("anyOf") {
            merge(object);
        }
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_errors(sources: &[&str]) -> String {
        parse_bundle_sources(sources).unwrap_err()
    }

    #[test]
    fn bundles_inline_local_definitions_and_merge_disjoint_files() {
        let first = r##"{
            "definitions": {
                "key": {"type": "string"},
                "item": {"type": "object", "properties": {"key": {"$ref": "#/definitions/key", "description": "Item key."}}}
            },
            "actions": {
                "item.view": {
                    "success": {"type": "object", "properties": {"item": {"$ref": "#/definitions/item"},
                        "items": {"type": "array", "items": {"$ref": "#/definitions/item"}},
                        "either": {"anyOf": [{"$ref": "#/definitions/key"}, {"type": "null"}]}}},
                    "error": {"type": "object", "properties": {"key": {"$ref": "#/definitions/key"}}}
                }
            }
        }"##;
        let second = r##"{"definitions": {"key": {"type": "integer"}},
            "actions": {"item.list": {"success": {"type": "object", "properties": {"key": {"$ref": "#/definitions/key"}}}}}}"##;
        let parsed = parse_bundle_sources(&[first, second]).unwrap();
        let view = &parsed["item.view"];
        assert_eq!(
            view.success()["properties"]["item"],
            json!({"type": "object", "properties": {"key": {"type": "string", "description": "Item key."}}})
        );
        assert_eq!(
            view.success()["properties"]["items"]["items"]["properties"]["key"]["type"],
            "string"
        );
        assert_eq!(
            view.success()["properties"]["either"]["anyOf"][0],
            json!({"type": "string"})
        );
        assert_eq!(view.error().unwrap()["properties"]["key"]["type"], "string");
        // Each file's references resolve in that file only.
        assert_eq!(
            parsed["item.list"].success()["properties"]["key"]["type"],
            "integer"
        );
        assert!(parsed["item.list"].error().is_none());
        assert!(
            !serde_json::to_string(view.success())
                .unwrap()
                .contains("$ref")
        );
    }

    #[test]
    fn bundles_reject_recursion_unknown_references_and_overlap() {
        let recursive = r##"{"definitions": {"node": {"type": "object", "properties": {"child": {"$ref": "#/definitions/node"}}}},
            "actions": {"item.view": {"success": {"$ref": "#/definitions/node"}}}}"##;
        assert!(bundle_errors(&[recursive]).contains("node refers to itself"));
        let mutual = r##"{"definitions": {"a": {"anyOf": [{"$ref": "#/definitions/b"}]}, "b": {"items": {"$ref": "#/definitions/a"}}},
            "actions": {"item.view": {"success": {"$ref": "#/definitions/a"}}}}"##;
        assert!(bundle_errors(&[mutual]).contains("refers to itself"));
        let missing = r##"{"actions": {"item.view": {"success": {"type": "object", "properties": {"a": {"$ref": "#/definitions/absent"}}}}}}"##;
        assert!(bundle_errors(&[missing]).contains("definition absent does not exist"));
        let external = r##"{"actions": {"item.view": {"success": {"$ref": "other.json#/x"}}}}"##;
        assert!(bundle_errors(&[external]).contains("#/definitions/<name>"));
        let sibling = r##"{"definitions": {"a": {"type": "string"}}, "actions": {"item.view": {"success": {"$ref": "#/definitions/a", "type": "object"}}}}"##;
        assert!(bundle_errors(&[sibling]).contains("unsupported sibling type"));
        let one = r#"{"actions": {"item.view": {"success": {"type": "object"}}}}"#;
        assert!(bundle_errors(&[one, one]).contains("more than one file"));
        for (source, expected) in [
            ("[]", "must be a JSON object"),
            (
                r#"{"actions": {}, "extra": 1}"#,
                "unsupported top-level key extra",
            ),
            (r#"{"definitions": {}}"#, "needs an actions object"),
            (
                r#"{"actions": {"item.view": {}}}"#,
                "needs a success schema",
            ),
            (
                r#"{"actions": {"item.view": {"success": {}, "other": {}}}}"#,
                "unsupported key other",
            ),
            ("{", "invalid JSON"),
        ] {
            assert!(bundle_errors(&[source]).contains(expected), "{source}");
        }
    }

    #[test]
    fn static_bundles_parse_once_and_list_their_actions() {
        static BUNDLE: ResultSchemaBundle = ResultSchemaBundle::new(&[
            r#"{"actions": {"b.view": {"success": {"type": "object"}}}}"#,
            r#"{"actions": {"a.view": {"success": {"type": "object"}, "error": {"type": "object"}}}}"#,
        ]);
        assert_eq!(BUNDLE.actions(), ["a.view", "b.view"]);
        assert!(BUNDLE.action("a.view").error().is_some());
        assert!(std::ptr::eq(BUNDLE.parsed(), BUNDLE.parsed()));
        assert!(format!("{BUNDLE:?}").contains("sources: 2"));
        let missing = std::panic::catch_unwind(|| BUNDLE.action("c.view")).unwrap_err();
        assert_eq!(
            missing.downcast_ref::<String>().unwrap(),
            "bundled result schemas declare no entry for c.view"
        );
    }

    fn validation_errors(schemas: ActionResultSchemas, owners: &[&str]) -> Vec<String> {
        let owners = owners
            .iter()
            .map(|owner| owner.to_string())
            .collect::<Vec<_>>();
        let mut errors = Vec::new();
        validate_action_result_schemas("example.item.view", &schemas, &owners, &mut errors);
        errors
    }

    #[test]
    fn profile_accepts_the_portable_subset() {
        let success = json!({
            "type": "object",
            "description": "One item.",
            "properties": {
                "id": {"type": "string", "minLength": 1, "maxLength": 64},
                "state": {"type": "string", "enum": ["open", "closed"]},
                "kind": {"const": "item"},
                "count": {"type": "integer", "minimum": 0, "maximum": 10},
                "parent": {"type": ["object", "null"], "properties": {"id": {"type": "string"}}},
                "labels": {"type": "array", "items": {"type": "string"}, "minItems": 0, "maxItems": 5},
                "fields": {"type": "object", "additionalProperties": {"anyOf": [{"type": "string"}, {"type": "null"}]}},
                "closed": {"type": "object", "additionalProperties": false},
                "opaque": {}
            },
            "required": ["id", "state"]
        });
        assert_eq!(
            validation_errors(
                ActionResultSchemas::new(success).with_error(json!({"type": "object"})),
                &[]
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn profile_rejects_keywords_roots_and_malformed_values() {
        for (keyword, value) in [
            (
                "$schema",
                json!("https://json-schema.org/draft/2020-12/schema"),
            ),
            ("$id", json!("item")),
            ("$defs", json!({})),
            ("$ref", json!("#/definitions/item")),
            ("format", json!("date-time")),
            ("pattern", json!("^a")),
            ("allOf", json!([{}])),
            ("oneOf", json!([{}])),
            ("not", json!({})),
            ("if", json!({})),
            ("then", json!({})),
            ("else", json!({})),
            ("prefixItems", json!([{}])),
            ("contains", json!({})),
            ("dependencies", json!({})),
            ("dependentRequired", json!({})),
            ("unevaluatedProperties", json!(false)),
            ("$anchor", json!("item")),
            ("default", json!("x")),
            ("examples", json!(["x"])),
            ("title", json!("Item")),
        ] {
            let mut schema = json!({"type": "object", "properties": {"id": {"type": "string"}}});
            schema["properties"]["id"][keyword] = value;
            assert_eq!(
                validation_errors(ActionResultSchemas::new(schema), &[]),
                [format!(
                    "example.item.view success result schema: /properties/id uses keyword {keyword} outside the result schema profile"
                )],
            );
        }
        for (schema, problem) in [
            (json!({"type": "array"}), "root must describe an object"),
            (
                json!({"type": ["object", "null"]}),
                "root must describe an object",
            ),
            (
                json!({"type": "object", "properties": {"a": {"type": "date"}}}),
                "/properties/a/type must name distinct JSON types",
            ),
            (
                json!({"type": "object", "properties": {"a": {"type": ["string", "string"]}}}),
                "/properties/a/type must name distinct JSON types",
            ),
            (
                json!({"type": "object", "properties": {"a": {"items": [{}]}}}),
                "/properties/a/items must be a schema object",
            ),
            (
                json!({"type": "object", "properties": {"a": true}}),
                "/properties/a must be a schema object",
            ),
            (
                json!({"type": "object", "required": ["a"]}),
                "/required must list distinct names its properties declare",
            ),
            (
                json!({"type": "object", "properties": {"a": {}}, "required": ["a", "a"]}),
                "/required must list distinct names its properties declare",
            ),
            (
                json!({"type": "object", "properties": {"a": {"anyOf": []}}}),
                "/properties/a/anyOf must be a non-empty array",
            ),
            (
                json!({"type": "object", "properties": {"a": {"enum": []}}}),
                "/properties/a/enum must be a non-empty array",
            ),
            (
                json!({"type": "object", "properties": {"a": {"minLength": -1}}}),
                "/properties/a/minLength must be a non-negative integer",
            ),
            (
                json!({"type": "object", "properties": {"a": {"maximum": "1"}}}),
                "/properties/a/maximum must be a number",
            ),
            (
                json!({"type": "object", "description": 1}),
                "/description must be a string",
            ),
        ] {
            assert_eq!(
                validation_errors(ActionResultSchemas::new(schema.clone()), &[]),
                [format!(
                    "example.item.view success result schema: {problem}"
                )],
                "{schema}"
            );
        }
        assert_eq!(
            validation_errors(
                ActionResultSchemas::new(json!({"type": "object"}))
                    .with_error(json!({"type": "string"})),
                &[]
            ),
            ["example.item.view error result schema: root must describe an object"]
        );
    }

    #[test]
    fn validation_enforces_the_size_budget_after_inlining() {
        let description = |bytes: usize| "x".repeat(bytes);
        let base = serde_json::to_vec(&json!({"type": "object", "description": ""}))
            .unwrap()
            .len();
        let exact = ActionResultSchemas::new(
            json!({"type": "object", "description": description(RESULT_SCHEMAS_MAX_BYTES - base)}),
        );
        assert!(validation_errors(exact, &[]).is_empty());
        let split =
            ActionResultSchemas::new(json!({"type": "object", "description": description(4000)}))
                .with_error(json!({"type": "object", "description": description(4200)}));
        assert_eq!(
            validation_errors(split, &[]),
            ["example.item.view result schemas exceed 8192 bytes"]
        );
    }

    #[test]
    fn validation_requires_rendered_body_owners_to_resolve() {
        let success = json!({"type": "object", "properties": {
            "body": {"type": "string"},
            "comments": {"type": "array", "items": {"type": "object", "properties": {"body": {}}}}
        }});
        assert!(
            validation_errors(
                ActionResultSchemas::new(success.clone()),
                &["", "/comments/*"]
            )
            .is_empty()
        );
        assert_eq!(
            validation_errors(
                ActionResultSchemas::new(success),
                &["/notes/*", "/comments/*/author"]
            ),
            [
                "example.item.view success result schema does not resolve rendered body owner /notes/*",
                "example.item.view success result schema does not resolve rendered body owner /comments/*/author",
            ]
        );
    }

    #[test]
    fn shared_failure_properties_merge_without_replacing_provider_declarations() {
        let shared = shared_failure_result_schema();
        assert!(shared.get("required").is_none());
        assert!(shared.get("additionalProperties").is_none());
        assert!(
            shared["properties"]["safeLocators"]
                .get("properties")
                .is_none()
        );
        let merged = with_shared_failure_properties(&json!({
            "type": "object",
            "properties": {"conflict": {"type": "boolean"}, "mutationStatus": {"const": "unknown"}}
        }));
        assert_eq!(merged["properties"]["conflict"], json!({"type": "boolean"}));
        assert_eq!(
            merged["properties"]["mutationStatus"],
            json!({"const": "unknown"})
        );
        assert_eq!(
            merged["properties"]["retryAfterSeconds"],
            json!({"type": "integer"})
        );
        assert!(shared["properties"]["retryAfterSeconds"]["description"].is_string());
        let branches = with_shared_failure_properties(&json!({"type": "object", "anyOf": [
            {"type": "object", "properties": {"a": {"type": "string"}}},
            {"type": "object", "properties": {"retrySafe": {"const": false}}}
        ]}));
        assert!(branches.get("properties").is_none());
        assert_eq!(branches["anyOf"][0]["properties"]["a"]["type"], "string");
        assert_eq!(
            branches["anyOf"][0]["properties"]["executionState"]["type"],
            "string"
        );
        assert_eq!(
            branches["anyOf"][1]["properties"]["retrySafe"],
            json!({"const": false})
        );
        assert!(jsonschema::validator_for(&branches).is_ok());
    }
}
