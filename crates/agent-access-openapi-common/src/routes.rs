use crate::{
    GATEWAY_MAX_MANIFEST_BYTES, GATEWAY_MAX_PATHS, GatewayRouteManifestV1, GatewayRouteV1, bounded,
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
    pub canonical_path: String,
    pub parameters: BTreeMap<String, String>,
    pub route: Option<&'a GatewayRouteV1>,
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

fn encode_segment(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
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

/// Decode exactly once and reconstruct from those components, retaining a meaningful trailing slash.
pub fn canonical_path(path: &str) -> Result<String, String> {
    Ok(format!(
        "/{}",
        decoded_path(path)?
            .iter()
            .map(|part| encode_segment(part))
            .collect::<Vec<_>>()
            .join("/")
    ))
}

fn segments(path: &str) -> Result<Vec<Segment>, String> {
    let parts = decoded_path(path)?;
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

    /// Select the most specific source path before selecting its exact method.
    /// `None` and an absent/inactive route are indistinguishable denial targets to HTTP callers.
    pub fn select<'a>(
        &'a self,
        method: &str,
        path: &str,
    ) -> Result<Option<GatewayPathMatch<'a>>, String> {
        let components = decoded_path(path)?;
        let canonical_path = canonical_path(path)?;
        let mut selected = None;
        let mut specificity = 0;
        for (template, guard) in &self.paths {
            let pattern = segments(template)?;
            if components.len() != pattern.len() {
                continue;
            }
            let mut parameters = BTreeMap::new();
            let mut score = 0;
            let matches = pattern
                .iter()
                .zip(&components)
                .all(|(part, value)| match part {
                    Segment::Literal(literal) => {
                        score += 1;
                        literal == value
                    }
                    Segment::Parameter(name) if !value.is_empty() => {
                        parameters.insert(name.clone(), value.clone());
                        true
                    }
                    Segment::Parameter(_) => false,
                });
            if matches && (selected.is_none() || score > specificity) {
                specificity = score;
                selected = Some(GatewayPathMatch {
                    template,
                    canonical_path: canonical_path.clone(),
                    parameters,
                    route: guard.methods.get(method),
                });
            }
        }
        Ok(selected)
    }
}

impl Default for GatewayRouteManifestV1 {
    fn default() -> Self {
        Self::empty()
    }
}
