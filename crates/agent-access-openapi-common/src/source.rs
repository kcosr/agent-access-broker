//! Neutral local source semantics; no network access and no import settings or credentials.
use crate::{GATEWAY_MAX_DEPTH, GatewayCompileOptions, bounded, validate_endpoint};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use url::{Position, Url};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    OpenApi31,
    Swagger2,
}

impl Dialect {
    pub fn identify(document: &Value) -> Result<(Self, String), String> {
        document
            .as_object()
            .ok_or("definition must be a JSON object")?;
        match (document.get("openapi"), document.get("swagger")) {
            (Some(Value::String(version)), None) if version.strip_prefix("3.1.").is_some_and(|patch| !patch.is_empty() && patch.len() <= 4 && patch.bytes().all(|b| b.is_ascii_digit())) => {
                if document.get("jsonSchemaDialect").is_some_and(|v| !matches!(v.as_str(), Some("https://spec.openapis.org/oas/3.1/dialect/base" | "https://json-schema.org/draft/2020-12/schema"))) {
                    return Err("unsupported OpenAPI JSON Schema dialect".into());
                }
                Ok((Self::OpenApi31, version.clone()))
            }
            (None, Some(Value::String(version))) if version == "2.0" => Ok((Self::Swagger2, version.clone())),
            _ => Err("definition requires exactly one supported version marker: swagger 2.0 or openapi 3.1.x".into()),
        }
    }

    fn prefix(self, category: &str) -> String {
        match self {
            Self::OpenApi31 => format!("/components/{category}/"),
            Self::Swagger2 => format!(
                "/{}/",
                if category == "schemas" {
                    "definitions"
                } else {
                    category
                }
            ),
        }
    }

    /// Structural references are typed and local, with no semantic siblings or cycles.
    pub fn object<'a>(
        self,
        document: &'a Value,
        value: &'a Value,
        category: &str,
    ) -> Result<&'a Value, String> {
        let mut current = value;
        let mut seen = BTreeSet::new();
        for _ in 0..32 {
            let fields = current
                .as_object()
                .ok_or("referenced value must be an object")?;
            let Some(reference) = fields.get("$ref") else {
                return Ok(current);
            };
            if fields
                .keys()
                .any(|key| !matches!(key.as_str(), "$ref" | "summary" | "description"))
            {
                return Err(
                    "structural references support only summary and description siblings".into(),
                );
            }
            let pointer = pointer(reference.as_str().ok_or("invalid local reference")?)?;
            if !pointer.starts_with(&self.prefix(category)) || !seen.insert(pointer.clone()) {
                return Err("reference is cyclic or outside its typed local collection".into());
            }
            current = document
                .pointer(&pointer)
                .ok_or("local reference target is missing")?;
        }
        Err("local reference chain exceeds its limit".into())
    }

    /// Body schemas are retained only as documentation semantics, but references remain local/bounded.
    pub fn documentation_schema(self, document: &Value, schema: &Value) -> Result<(), String> {
        if !schema.is_object() && !(self == Self::OpenApi31 && schema.is_boolean()) {
            return Err("body schema has an invalid shape".into());
        }
        let mut queue = vec![(schema, 0usize)];
        let mut seen = BTreeSet::new();
        let mut visited = 0usize;
        while let Some((value, depth)) = queue.pop() {
            visited += 1;
            if visited > 8192 {
                return Err("body schema exceeds its node budget".into());
            }
            if depth > GATEWAY_MAX_DEPTH {
                return Err("body schema reference depth exceeds its limit".into());
            }
            match value {
                Value::Object(fields) => {
                    if let Some(reference) = fields.get("$ref") {
                        let pointer =
                            pointer(reference.as_str().ok_or("invalid body schema reference")?)?;
                        if !pointer.starts_with(&self.prefix("schemas")) {
                            return Err(
                                "body schema reference must target local schema components".into(),
                            );
                        }
                        if seen.insert(pointer.clone()) {
                            if seen.len() > 256 {
                                return Err("body schema exceeds its local reference limit".into());
                            }
                            queue.push((
                                document
                                    .pointer(&pointer)
                                    .ok_or("body schema reference target is missing")?,
                                depth + 1,
                            ));
                        }
                    }
                    // Traverse schema-bearing fields only; examples may legitimately contain `$ref` data.
                    for (key, child) in fields {
                        match key.as_str() {
                            "properties" | "patternProperties" | "$defs" | "definitions"
                            | "dependentSchemas" => {
                                for child in child
                                    .as_object()
                                    .ok_or("body schema map has an invalid shape")?
                                    .values()
                                {
                                    queue.push((child, depth + 1));
                                }
                            }
                            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                                for child in child
                                    .as_array()
                                    .ok_or("body schema alternatives have an invalid shape")?
                                {
                                    queue.push((child, depth + 1));
                                }
                            }
                            "items"
                            | "additionalProperties"
                            | "unevaluatedProperties"
                            | "propertyNames"
                            | "contains"
                            | "not"
                            | "if"
                            | "then"
                            | "else"
                            | "contentSchema" => queue.push((child, depth + 1)),
                            _ => {}
                        }
                    }
                }
                Value::Bool(_) => {}
                _ => return Err("body schema node has an invalid shape".into()),
            }
        }
        Ok(())
    }
}

fn pointer(raw: &str) -> Result<String, String> {
    let fragment = raw
        .strip_prefix('#')
        .ok_or("external references are unsupported")?;
    let bytes = fragment.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err("invalid local reference encoding".into());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    let pointer = percent_encoding::percent_decode_str(fragment)
        .decode_utf8()
        .map_err(|_| "invalid local reference encoding")?;
    if !pointer.starts_with('/') {
        return Err("only local JSON Pointer references are supported".into());
    }
    Ok(pointer.into_owned())
}

pub(crate) fn destinations(
    dialect: Dialect,
    document: &Value,
    item: &Value,
    operation: &Value,
    options: &GatewayCompileOptions,
) -> Result<(), String> {
    let endpoint = validate_endpoint(&options.endpoint)?;
    let base = validate_endpoint(&options.document_base)?;
    let candidates = match dialect {
        Dialect::OpenApi31 => {
            let Some(servers) = operation
                .get("servers")
                .or_else(|| item.get("servers"))
                .or_else(|| document.get("servers"))
            else {
                return Ok(());
            };
            let servers = servers
                .as_array()
                .filter(|v| !v.is_empty() && v.len() <= 32)
                .ok_or("servers must be a bounded nonempty array")?;
            let mut candidates = Vec::new();
            for server in servers {
                let mut raw = server
                    .get("url")
                    .and_then(Value::as_str)
                    .filter(|v| bounded(v, 4096))
                    .ok_or("server URL is invalid")?
                    .to_owned();
                if let Some(variables) = server.get("variables") {
                    for (name, value) in variables
                        .as_object()
                        .ok_or("server variables must be an object")?
                    {
                        let default = value
                            .get("default")
                            .and_then(Value::as_str)
                            .filter(|v| bounded(v, 256) && !v.contains(['{', '}']))
                            .ok_or("server variable requires a fixed bounded default")?;
                        if value.get("enum").is_some_and(|v| {
                            v.as_array()
                                .is_none_or(|values| !values.contains(&json!(default)))
                        }) {
                            return Err("server variable default is outside its enum".into());
                        }
                        raw = raw.replace(&format!("{{{name}}}"), default);
                    }
                }
                if raw.contains(['{', '}']) {
                    return Err("unresolved server variables are unsupported".into());
                }
                let url = base.join(&raw).map_err(|_| "invalid source server URL")?;
                candidates.push(validate_endpoint(url.as_str())?);
            }
            candidates
        }
        Dialect::Swagger2 => {
            let host = document
                .get("host")
                .map(|v| {
                    v.as_str()
                        .filter(|v| bounded(v, 512))
                        .ok_or("invalid Swagger host")
                })
                .transpose()?
                .unwrap_or(&base[Position::BeforeHost..Position::AfterPort]);
            if host.contains(['/', '\\', '@', '?', '#', '%'])
                || host.chars().any(char::is_whitespace)
            {
                return Err("Swagger host must be a host and optional port".into());
            }
            let path = document
                .get("basePath")
                .map(|v| v.as_str().ok_or("Swagger basePath must be a string"))
                .transpose()?
                .unwrap_or("/");
            if path.contains(['%', '{', '}']) {
                return Err("invalid Swagger basePath".into());
            }
            crate::canonical_path(path)?;
            let fallback = vec![json!(base.scheme())];
            let schemes = operation
                .get("schemes")
                .or_else(|| document.get("schemes"))
                .map(|v| v.as_array().ok_or("Swagger schemes must be an array"))
                .transpose()?
                .unwrap_or(&fallback);
            if schemes.is_empty() || schemes.len() > 8 {
                return Err("Swagger schemes must be bounded and nonempty".into());
            }
            schemes
                .iter()
                .map(|scheme| {
                    let scheme = scheme
                        .as_str()
                        .filter(|v| matches!(*v, "http" | "https"))
                        .ok_or("unsupported Swagger scheme")?;
                    validate_endpoint(&format!("{scheme}://{host}{path}"))
                })
                .collect::<Result<Vec<Url>, String>>()?
        }
    };
    if candidates.iter().any(|candidate| {
        candidate.as_str().trim_end_matches('/') == endpoint.as_str().trim_end_matches('/')
    }) {
        Ok(())
    } else {
        Err("operation has no server matching the approved API endpoint".into())
    }
}
