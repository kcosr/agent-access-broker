//! Attribution footer capabilities and their configuration matching.
use crate::ServiceDescriptor;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AttributionVerb {
    Add,
    Update,
}

impl AttributionVerb {
    pub fn footer_text(self, broker_request_id: &str) -> String {
        match self {
            Self::Add => format!("Added via Agent Access Broker. Request ID: {broker_request_id}"),
            Self::Update => {
                format!("Updated via Agent Access Broker. Request ID: {broker_request_id}")
            }
        }
    }

    pub fn audit_value(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Update => "update",
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributionRepresentation {
    Adf,
    ConfluenceStorage,
    GitlabMarkdown,
}

impl AttributionRepresentation {
    pub fn audit_value(self) -> &'static str {
        match self {
            Self::Adf => "adf",
            Self::ConfluenceStorage => "storage",
            Self::GitlabMarkdown => "markdown",
        }
    }
}

/// How an action can carry an attribution footer. Backends declare this on
/// their action descriptors with [`Self::required`] or [`Self::optional`];
/// configuration selects which ones are active.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributionCapability {
    pub verb: AttributionVerb,
    pub target: &'static str,
    pub representation: AttributionRepresentation,
    /// Whether the target is always present, so a missing target is an
    /// error rather than a skipped footer.
    pub required: bool,
}

impl AttributionCapability {
    pub const fn required(
        verb: AttributionVerb,
        target: &'static str,
        representation: AttributionRepresentation,
    ) -> Self {
        Self {
            verb,
            target,
            representation,
            required: true,
        }
    }

    pub const fn optional(
        verb: AttributionVerb,
        target: &'static str,
        representation: AttributionRepresentation,
    ) -> Self {
        Self {
            verb,
            target,
            representation,
            required: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProviderAttributionConfig {
    capabilities: BTreeMap<String, AttributionCapability>,
}

impl ProviderAttributionConfig {
    /// Active attribution for a service: its descriptor's capabilities
    /// selected by the configured action patterns.
    pub fn from_patterns(descriptor: &ServiceDescriptor, patterns: &[String]) -> Self {
        let mut capabilities = BTreeMap::new();
        for pattern in patterns {
            if validate_attribution_pattern(pattern).is_err() {
                continue;
            }
            for (action, capability) in matching_attribution_capabilities(descriptor, pattern) {
                capabilities.insert(action.to_string(), capability);
            }
        }
        Self { capabilities }
    }

    pub fn capability(&self, action: &str) -> Option<AttributionCapability> {
        self.capabilities.get(action).copied()
    }
}

/// An attribution footer a write applied, as its audit records it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributionMutation {
    pub target: &'static str,
    pub representation: &'static str,
    pub verb: &'static str,
    pub deduped: bool,
}

impl AttributionMutation {
    pub fn new(capability: AttributionCapability, deduped: bool) -> Self {
        Self {
            target: capability.target,
            representation: capability.representation.audit_value(),
            verb: capability.verb.audit_value(),
            deduped,
        }
    }

    pub fn audit_value(&self) -> Value {
        json!({
            "applied": true,
            "target": self.target,
            "representation": self.representation,
            "verb": self.verb,
            "deduped": self.deduped,
        })
    }
}

pub fn attribution_skip_target_absent_audit() -> Value {
    json!({
        "applied": false,
        "skipReason": "target_absent",
    })
}

pub fn attribution_audit_applied(attribution: Option<&Value>) -> bool {
    attribution
        .and_then(|value| value.get("applied"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub fn merge_attribution_audit(audit: &mut Value, attribution: Option<Value>) {
    let Some(attribution) = attribution else {
        return;
    };
    if !audit.is_object() {
        *audit = json!({});
    }
    if let Some(object) = audit.as_object_mut() {
        object.insert("attribution".to_string(), attribution);
    }
}

/// Attribution-capable actions of `descriptor` whose names match `pattern`.
pub fn matching_attribution_capabilities<'a>(
    descriptor: &'a ServiceDescriptor,
    pattern: &'a str,
) -> impl Iterator<Item = (&'a str, AttributionCapability)> + 'a {
    descriptor.actions.iter().filter_map(move |action| {
        let capability = action.attribution?;
        glob_matches(pattern, &action.action).then_some((action.action.as_str(), capability))
    })
}

/// Checks an `attribution.actions` glob pattern.
pub fn validate_attribution_pattern(pattern: &str) -> Result<(), &'static str> {
    if pattern.is_empty() {
        return Err("must not be empty");
    }
    if pattern.len() > 128 {
        return Err("must not exceed 128 bytes");
    }
    if !pattern.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'*' | b'?')
    }) {
        return Err("contains unsupported glob characters");
    }
    Ok(())
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v) = (0, 0);
    let mut star = None;
    let mut match_after_star = 0;
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            match_after_star = v;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            match_after_star += 1;
            v = match_after_star;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}
