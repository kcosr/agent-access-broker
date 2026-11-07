use crate::{
    GATEWAY_MAX_MANIFEST_BYTES, GATEWAY_MAX_PATHS, GatewayPathV1, GatewayRouteManifestV1,
    GatewayRouteV1, bounded,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const PATH_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Parameter(String),
}

/// A selected path is authoritative even when its method or operation is unavailable.
#[derive(Debug)]
pub struct GatewayPathMatch<'a> {
    pub template: &'a str,
    /// Forwarding path reconstructed from the selected template: literal pchar
    /// stays literal; captured parameter values use unreserved-only encoding.
    pub canonical_path: String,
    pub parameters: BTreeMap<String, String>,
    pub route: Option<&'a GatewayRouteV1>,
}

/// An immutable publication snapshot with precompiled segments, grouped by path length.
/// This runtime index is deliberately separate from the durable V1 wire representation.
#[derive(Clone, Debug)]
pub struct GatewayRouteMatcher {
    paths: BTreeMap<usize, Vec<CompiledPath>>,
}

#[derive(Clone, Debug)]
struct CompiledPath {
    template: String,
    guard: GatewayPathV1,
    segments: Vec<Segment>,
}

fn decode_segment(raw: &str) -> Result<String, String> {
    let mut index = 0;
    let bytes = raw.as_bytes();
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err("gateway path contains an invalid escape".into());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| "gateway path is not UTF-8")?
        .into_owned();
    if decoded == "."
        || decoded == ".."
        || decoded.contains(['/', '\\', '%'])
        || decoded.chars().any(char::is_control)
    {
        return Err("gateway path contains an unsafe component".into());
    }
    Ok(decoded)
}

fn encode_segment(value: &str, literal: bool) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        // RFC 3986 pchar includes sub-delimiters, colon and at-sign. Escaping
        // these changes raw-path routing semantics for literal custom verbs.
        if byte.is_ascii_alphanumeric()
            || b"-._~".contains(&byte)
            || literal && b"!$&'()*+,;=:@".contains(&byte)
        {
            result.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut result, "%{byte:02X}").expect("String write");
        }
    }
    result
}

fn decoded_path(path: &str) -> Result<Vec<String>, String> {
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.len() > PATH_BYTES
        || path.contains(['?', '#', '\\'])
        || path.chars().any(char::is_control)
    {
        return Err("gateway path must be a bounded relative path".into());
    }
    let parts = path[1..]
        .split('/')
        .map(decode_segment)
        .collect::<Result<Vec<_>, _>>()?;
    if parts.len() > 128
        || parts[..parts.len().saturating_sub(1)]
            .iter()
            .any(String::is_empty)
    {
        return Err("gateway path has empty or excessive components".into());
    }
    Ok(parts)
}

/// Normalize an unbound/source path once, retaining literal pchar and a meaningful trailing slash.
/// Forward requests using the selected matcher result's `canonical_path`, which also constrains
/// captured parameter values according to their template role.
pub fn canonical_path(path: &str) -> Result<String, String> {
    Ok(encode_components(&decoded_path(path)?))
}

fn encode_components(components: &[String]) -> String {
    format!(
        "/{}",
        components
            .iter()
            .map(|part| encode_segment(part, true))
            .collect::<Vec<_>>()
            .join("/")
    )
}

fn segments(path: &str) -> Result<Vec<Segment>, String> {
    let parts = decoded_path(path)?;
    if parts.iter().any(|part| part.contains(';')) {
        return Err("matrix/path parameters are unsupported in gateway source paths".into());
    }
    let mut names = BTreeSet::new();
    parts
        .into_iter()
        .map(|part| {
            if let Some(name) = part.strip_prefix('{').and_then(|v| v.strip_suffix('}')) {
                if !bounded(name, 256)
                    || name.contains(['{', '}', '*', ':'])
                    || !names.insert(name.to_owned())
                {
                    return Err("gateway path template has an invalid or repeated parameter".into());
                }
                Ok(Segment::Parameter(name.to_owned()))
            } else if part.contains(['{', '}', '*']) {
                Err("gateway path parameters must occupy whole segments".into())
            } else {
                Ok(Segment::Literal(part))
            }
        })
        .collect()
}

/// Validate a guard template and return its ordered parameter names.
pub fn validate_path_template(path: &str) -> Result<Vec<String>, String> {
    if path.contains('%') {
        return Err(
            "source path templates must use literal UTF-8 rather than percent escapes".into(),
        );
    }
    Ok(segments(path)?
        .into_iter()
        .filter_map(|part| match part {
            Segment::Parameter(name) => Some(name),
            Segment::Literal(_) => None,
        })
        .collect())
}

fn overlap(left: &[Segment], right: &[Segment]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(a, b)| match (a, b) {
            (Segment::Literal(a), Segment::Literal(b)) => a == b,
            (Segment::Parameter(_), Segment::Literal(b))
            | (Segment::Literal(b), Segment::Parameter(_)) => !b.is_empty(),
            _ => true,
        })
}

fn refines(left: &[Segment], right: &[Segment]) -> bool {
    left.iter().zip(right).all(|(a, b)| match (a, b) {
        (Segment::Literal(a), Segment::Literal(b)) => a == b,
        (Segment::Literal(_), Segment::Parameter(_))
        | (Segment::Parameter(_), Segment::Parameter(_)) => true,
        _ => false,
    })
}

pub(crate) fn validate_source(source: &Value, method: &str, path: &str) -> Result<(), String> {
    let source = source
        .as_object()
        .ok_or("invalid gateway operation source")?;
    if source.len() == 1
        && source
            .get("operationId")
            .and_then(Value::as_str)
            .is_some_and(|id| bounded(id, 256))
        || source.len() == 2
            && source.get("method").and_then(Value::as_str) == Some(method)
            && source.get("path").and_then(Value::as_str) == Some(path)
    {
        Ok(())
    } else {
        Err("invalid gateway operation source".into())
    }
}

impl GatewayRouteManifestV1 {
    /// A newly created draft reserves its service identity before its first complete discovery.
    pub fn empty() -> Self {
        Self {
            version: 1,
            paths: BTreeMap::new(),
        }
    }

    /// Validate the full guard universe before publication or offline startup.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 || self.paths.len() > GATEWAY_MAX_PATHS {
            return Err("unsupported gateway manifest version or path count".into());
        }
        if serde_json::to_vec(self)
            .map_err(|_| "invalid gateway manifest")?
            .len()
            > GATEWAY_MAX_MANIFEST_BYTES
        {
            return Err("gateway route manifest exceeds its byte limit".into());
        }
        let mut all = Vec::new();
        for (path, guard) in &self.paths {
            validate_path_template(path)?;
            all.push(segments(path)?);
            if guard.methods.len() > 9 {
                return Err("gateway path has too many methods".into());
            }
            for (method, route) in &guard.methods {
                if !matches!(
                    method.as_str(),
                    "GET"
                        | "HEAD"
                        | "POST"
                        | "PUT"
                        | "PATCH"
                        | "DELETE"
                        | "OPTIONS"
                        | "TRACE"
                        | "CONNECT"
                ) || route.supported && matches!(method.as_str(), "TRACE" | "CONNECT")
                {
                    return Err("gateway manifest has an invalid method".into());
                }
                validate_source(&route.source, method, path)?;
            }
        }
        for (index, left) in all.iter().enumerate() {
            for right in &all[index + 1..] {
                if overlap(left, right) {
                    let a = refines(left, right);
                    let b = refines(right, left);
                    if a == b {
                        return Err(
                            "equivalent or incomparable overlapping gateway path templates".into(),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Merge a complete refresh with historical denial reservations. The receiver is unchanged on error.
    pub fn merge_retained(&mut self, old: &Self) -> Result<(), String> {
        self.validate()?;
        old.validate()?;
        let mut merged = old.clone();
        for guard in merged.paths.values_mut() {
            for route in guard.methods.values_mut() {
                route.current = false;
            }
        }
        for (path, guard) in &self.paths {
            let retained = merged
                .paths
                .entry(path.clone())
                .or_insert_with(|| guard.clone());
            for (method, route) in &guard.methods {
                retained.methods.insert(method.clone(), route.clone());
            }
        }
        merged.validate()?;
        *self = merged;
        Ok(())
    }

    /// Build once during publication; requests reuse its validated segment index.
    pub fn matcher(&self) -> Result<GatewayRouteMatcher, String> {
        self.validate()?;
        let mut paths: BTreeMap<usize, Vec<CompiledPath>> = BTreeMap::new();
        for (template, guard) in &self.paths {
            let segments = segments(template)?;
            paths.entry(segments.len()).or_default().push(CompiledPath {
                template: template.clone(),
                guard: guard.clone(),
                segments,
            });
        }
        Ok(GatewayRouteMatcher { paths })
    }

    /// Select the most specific source path before selecting its exact method.
    /// `None` and an absent/inactive route are indistinguishable denial targets to HTTP callers.
    pub fn select<'a>(
        &'a self,
        method: &str,
        path: &str,
    ) -> Result<Option<GatewayPathMatch<'a>>, String> {
        let components = decoded_path(path)?;
        let mut paths = Vec::with_capacity(self.paths.len());
        for (template, guard) in &self.paths {
            paths.push((template.as_str(), guard, segments(template)?));
        }
        select_components(
            method,
            &components,
            paths
                .iter()
                .map(|(template, guard, segments)| (*template, *guard, segments.as_slice())),
        )
    }
}

impl GatewayRouteMatcher {
    /// Select the complete source path before its exact method, using the immutable publication index.
    pub fn select(&self, method: &str, path: &str) -> Result<Option<GatewayPathMatch<'_>>, String> {
        let components = decoded_path(path)?;
        select_components(
            method,
            &components,
            self.paths
                .get(&components.len())
                .into_iter()
                .flatten()
                .map(|path| {
                    (
                        path.template.as_str(),
                        &path.guard,
                        path.segments.as_slice(),
                    )
                }),
        )
    }
}

fn select_components<'a, 'p>(
    method: &str,
    components: &[String],
    candidates: impl Iterator<Item = (&'a str, &'a GatewayPathV1, &'p [Segment])>,
) -> Result<Option<GatewayPathMatch<'a>>, String> {
    let mut selected = None;
    let mut specificity = 0;
    for (template, guard, pattern) in candidates {
        if components.len() != pattern.len() {
            continue;
        }
        let matches = pattern
            .iter()
            .zip(components)
            .all(|(part, value)| match part {
                Segment::Literal(literal) => literal == value,
                Segment::Parameter(_) => !value.is_empty(),
            });
        if !matches {
            continue;
        }
        let score = pattern
            .iter()
            .filter(|part| matches!(part, Segment::Literal(_)))
            .count();
        if selected.is_none() || score > specificity {
            specificity = score;
            selected = Some((template, guard, pattern));
        }
    }
    let Some((template, guard, pattern)) = selected else {
        return Ok(None);
    };
    let mut parameters = BTreeMap::new();
    let mut encoded = Vec::with_capacity(pattern.len());
    for (part, value) in pattern.iter().zip(components) {
        match part {
            Segment::Parameter(name) => {
                // Some backends strip semicolon suffixes before routing. Do not
                // let template captures collapse onto an independently guarded
                // literal or a dot segment, regardless of decode ordering.
                if value.contains(';') {
                    return Err("gateway path parameter contains an unsafe component".into());
                }
                parameters.insert(name.clone(), value.clone());
                encoded.push(encode_segment(value, false));
            }
            Segment::Literal(literal) => encoded.push(encode_segment(literal, true)),
        }
    }
    Ok(Some(GatewayPathMatch {
        template,
        canonical_path: format!("/{}", encoded.join("/")),
        parameters,
        route: guard.methods.get(method),
    }))
}

impl Default for GatewayRouteManifestV1 {
    fn default() -> Self {
        Self::empty()
    }
}
