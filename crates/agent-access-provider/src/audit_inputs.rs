//! Explicit, reviewed projection of original invocation inputs into audit facts.
//!
//! A declaration never validates provider inputs or authorizes their values.
//! The host prepares it once against the input schema, then captures only its
//! selected values after invocation admission.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use unicode_general_category::{GeneralCategory, get_general_category};

pub(crate) mod host;

/// The action's ordered input-audit rules. Absence is represented by `None`
/// on the descriptor; an explicitly empty declaration is invalid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AuditInputProjection(Vec<AuditInputRule>);

impl AuditInputProjection {
    pub fn new(rules: impl IntoIterator<Item = AuditInputRule>) -> Self {
        Self(rules.into_iter().collect())
    }

    pub fn rules(&self) -> &[AuditInputRule] {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.0.is_empty() {
            return Err("auditInputs must contain at least one rule".into());
        }
        let mut count = 0;
        let mut keys = BTreeSet::new();
        validate_rules(&self.0, false, &mut count, &mut keys)
    }
}

impl<'de> Deserialize<'de> for AuditInputProjection {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Self(Vec::<AuditInputRule>::deserialize(deserializer)?);
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

macro_rules! audit_enum {
    ($(#[$attr:meta])* $name:ident { $($variant:ident),+ $(,)? }) => {
        $(#[$attr])*
        #[non_exhaustive]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub enum $name { $($variant),+ }
    };
}

audit_enum! { /// An explicitly approved operation on a selected input.
    AuditCapture { Value, Presence, ItemCount, Utf8ByteCount, Records, Omit }
}
audit_enum! { /// Value representation and presentation, never a sensitivity classification.
    AuditValueKind { Text, Query, Identifier, Path, Email, Date, Number, Boolean, Bytes, Records }
}
audit_enum! { /// The selected value's explicit container shape.
    AuditValueShape { Scalar, List }
}
audit_enum! { /// Retention priority and initial presentation. Raw values are still stored.
    AuditDisplay { Primary, Detail, Raw }
}
audit_enum! { /// A requested fact's presentation role; Change does not assert application.
    AuditRole { Target, Change, Fact }
}
audit_enum! { /// How an approved source string exceeding its cap is handled.
    AuditOverflow { Omit, Prefix }
}

/// A strict tagged rule built through the mode constructors and builders.
/// Publication validates legal options, selected paths and sensitivity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditInputRule {
    key: String,
    pointer: String,
    capture: AuditCapture,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display: Option<AuditDisplay>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<AuditRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<AuditValueKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shape: Option<AuditValueShape>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    overflow: Option<AuditOverflow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<AuditInputRule>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRule {
    key: String,
    pointer: String,
    capture: AuditCapture,
    #[serde(default, deserialize_with = "present_option")]
    label: Option<String>,
    #[serde(default, deserialize_with = "present_option")]
    display: Option<AuditDisplay>,
    #[serde(default, deserialize_with = "present_option")]
    role: Option<AuditRole>,
    #[serde(default, deserialize_with = "present_option")]
    kind: Option<AuditValueKind>,
    #[serde(default, deserialize_with = "present_option")]
    shape: Option<AuditValueShape>,
    #[serde(default, deserialize_with = "present_option")]
    max_bytes: Option<usize>,
    #[serde(default, deserialize_with = "present_option")]
    overflow: Option<AuditOverflow>,
    #[serde(default, deserialize_with = "present_option")]
    fields: Option<Vec<AuditInputRule>>,
}

fn present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl<'de> Deserialize<'de> for AuditInputRule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let rule = WireRule::deserialize(deserializer)?;
        let value = Self {
            key: rule.key,
            pointer: rule.pointer,
            capture: rule.capture,
            label: rule.label,
            display: rule.display,
            role: rule.role,
            kind: rule.kind,
            shape: rule.shape,
            max_bytes: rule.max_bytes,
            overflow: rule.overflow,
            fields: rule.fields,
        };
        value.validate_options().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl AuditInputRule {
    fn summary(
        key: impl Into<String>,
        label: impl Into<String>,
        pointer: impl Into<String>,
        capture: AuditCapture,
        kind: AuditValueKind,
    ) -> Self {
        Self {
            key: key.into(),
            pointer: pointer.into(),
            capture,
            label: Some(label.into()),
            display: Some(AuditDisplay::Detail),
            role: Some(AuditRole::Fact),
            kind: Some(kind),
            shape: None,
            max_bytes: None,
            overflow: None,
            fields: None,
        }
    }

    /// A scalar value. Select its kind and, for string-bearing kinds, its cap
    /// and overflow behavior explicitly before publication.
    pub fn value(
        key: impl Into<String>,
        label: impl Into<String>,
        pointer: impl Into<String>,
    ) -> Self {
        let mut rule = Self::summary(
            key,
            label,
            pointer,
            AuditCapture::Value,
            AuditValueKind::Text,
        );
        rule.shape = Some(AuditValueShape::Scalar);
        rule
    }

    /// A sample of scalar list items with one declared common kind.
    pub fn values(
        key: impl Into<String>,
        label: impl Into<String>,
        pointer: impl Into<String>,
    ) -> Self {
        let mut rule = Self::value(key, label, pointer);
        rule.shape = Some(AuditValueShape::List);
        rule
    }

    pub fn presence(
        key: impl Into<String>,
        label: impl Into<String>,
        pointer: impl Into<String>,
    ) -> Self {
        Self::summary(
            key,
            label,
            pointer,
            AuditCapture::Presence,
            AuditValueKind::Boolean,
        )
    }

    pub fn item_count(
        key: impl Into<String>,
        label: impl Into<String>,
        pointer: impl Into<String>,
    ) -> Self {
        Self::summary(
            key,
            label,
            pointer,
            AuditCapture::ItemCount,
            AuditValueKind::Number,
        )
    }

    pub fn utf8_byte_count(
        key: impl Into<String>,
        label: impl Into<String>,
        pointer: impl Into<String>,
    ) -> Self {
        Self::summary(
            key,
            label,
            pointer,
            AuditCapture::Utf8ByteCount,
            AuditValueKind::Bytes,
        )
    }

    pub fn records(
        key: impl Into<String>,
        label: impl Into<String>,
        pointer: impl Into<String>,
        fields: impl IntoIterator<Item = AuditInputRule>,
    ) -> Self {
        let mut rule = Self::summary(
            key,
            label,
            pointer,
            AuditCapture::Records,
            AuditValueKind::Records,
        );
        rule.fields = Some(fields.into_iter().collect());
        rule
    }

    /// A reviewed exclusion. It reads and emits no value, length or presence.
    pub fn omit(key: impl Into<String>, pointer: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            pointer: pointer.into(),
            capture: AuditCapture::Omit,
            label: None,
            display: None,
            role: None,
            kind: None,
            shape: None,
            max_bytes: None,
            overflow: None,
            fields: None,
        }
    }

    pub fn kind(mut self, kind: AuditValueKind) -> Self {
        self.kind = Some(kind);
        self
    }
    pub fn display(mut self, display: AuditDisplay) -> Self {
        self.display = Some(display);
        self
    }
    pub fn role(mut self, role: AuditRole) -> Self {
        self.role = Some(role);
        self
    }
    pub fn max_bytes(mut self, bytes: usize) -> Self {
        self.max_bytes = Some(bytes);
        self
    }
    pub fn overflow(mut self, overflow: AuditOverflow) -> Self {
        self.overflow = Some(overflow);
        self
    }

    pub fn key(&self) -> &str {
        &self.key
    }
    pub fn pointer(&self) -> &str {
        &self.pointer
    }
    pub fn capture(&self) -> AuditCapture {
        self.capture
    }
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
    pub fn display_placement(&self) -> Option<AuditDisplay> {
        self.display
    }
    pub fn value_role(&self) -> Option<AuditRole> {
        self.role
    }
    pub fn value_kind(&self) -> Option<AuditValueKind> {
        self.kind
    }
    pub fn value_shape(&self) -> Option<AuditValueShape> {
        self.shape
    }
    pub fn max_string_bytes(&self) -> Option<usize> {
        self.max_bytes
    }
    pub fn overflow_behavior(&self) -> Option<AuditOverflow> {
        self.overflow
    }
    pub fn fields(&self) -> &[AuditInputRule] {
        self.fields.as_deref().unwrap_or_default()
    }

    fn validate_options(&self) -> Result<(), String> {
        if self.key.is_empty()
            || self.key.len() > 64
            || !self
                .key
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'.'))
        {
            return Err(
                "auditInputs rule key must be 1..64 ASCII letters, digits, underscores or dots"
                    .into(),
            );
        }
        parse_pointer(&self.pointer)?;
        if self.capture == AuditCapture::Omit {
            if self.label.is_some()
                || self.display.is_some()
                || self.role.is_some()
                || self.kind.is_some()
                || self.shape.is_some()
                || self.max_bytes.is_some()
                || self.overflow.is_some()
                || self.fields.is_some()
            {
                return Err("auditInputs omit rule accepts only key, pointer and capture".into());
            }
            return Ok(());
        }
        let Some(label) = &self.label else {
            return Err("auditInputs rule requires label".into());
        };
        if label.is_empty()
            || label.len() > 80
            || label.chars().any(|ch| {
                matches!(
                    get_general_category(ch),
                    GeneralCategory::Control | GeneralCategory::Format
                )
            })
        {
            return Err(
                "auditInputs label must be 1..80 UTF-8 bytes without control or format characters"
                    .into(),
            );
        }
        if self.display.is_none() || self.role.is_none() || self.kind.is_none() {
            return Err("auditInputs rule requires display, role and kind".into());
        }
        let kind = self.kind.expect("checked kind");
        if self.capture == AuditCapture::Value {
            if self.shape.is_none() || kind == AuditValueKind::Records || self.fields.is_some() {
                return Err(
                    "auditInputs value requires scalar/list shape, a scalar kind and no fields"
                        .into(),
                );
            }
            if string_kind(kind) {
                if !matches!(self.max_bytes, Some(1..=4096)) || self.overflow.is_none() {
                    return Err(
                        "auditInputs string-bearing value requires maxBytes 1..4096 and overflow"
                            .into(),
                    );
                }
                if self.overflow == Some(AuditOverflow::Prefix)
                    && !matches!(kind, AuditValueKind::Text | AuditValueKind::Query)
                {
                    return Err("auditInputs only text and query permit prefix overflow".into());
                }
            } else if self.max_bytes.is_some() || self.overflow.is_some() {
                return Err("auditInputs non-string value forbids maxBytes and overflow".into());
            }
        } else {
            if self.shape.is_some() || self.max_bytes.is_some() || self.overflow.is_some() {
                return Err(
                    "auditInputs summary/records forbids shape, maxBytes and overflow".into(),
                );
            }
            let expected = match self.capture {
                AuditCapture::Presence => AuditValueKind::Boolean,
                AuditCapture::ItemCount => AuditValueKind::Number,
                AuditCapture::Utf8ByteCount => AuditValueKind::Bytes,
                AuditCapture::Records => AuditValueKind::Records,
                AuditCapture::Value | AuditCapture::Omit => unreachable!(),
            };
            if kind != expected || (self.capture == AuditCapture::Records) != self.fields.is_some()
            {
                return Err(
                    "auditInputs capture requires its fixed kind and records-only fields".into(),
                );
            }
            if self.fields.as_ref().is_some_and(Vec::is_empty) {
                return Err("auditInputs records requires at least one child rule".into());
            }
        }
        Ok(())
    }
}

pub(crate) fn string_kind(kind: AuditValueKind) -> bool {
    matches!(
        kind,
        AuditValueKind::Text
            | AuditValueKind::Query
            | AuditValueKind::Identifier
            | AuditValueKind::Path
            | AuditValueKind::Email
            | AuditValueKind::Date
    )
}

pub(crate) fn parse_pointer(pointer: &str) -> Result<Vec<String>, String> {
    if !pointer.starts_with('/') || pointer.len() > 1024 {
        return Err(
            "auditInputs pointer must be a non-root JSON Pointer of at most 1024 bytes".into(),
        );
    }
    let mut tokens = Vec::new();
    for encoded in pointer[1..].split('/') {
        if encoded.is_empty() {
            return Err("auditInputs pointer requires nonempty named segments".into());
        }
        let mut token = String::new();
        let mut chars = encoded.chars();
        while let Some(ch) = chars.next() {
            token.push(if ch == '~' {
                match chars.next() {
                    Some('0') => '~',
                    Some('1') => '/',
                    _ => return Err("auditInputs pointer has an invalid RFC 6901 escape".into()),
                }
            } else {
                ch
            });
        }
        if matches!(token.as_str(), "." | "..") {
            return Err("auditInputs pointer forbids parent traversal".into());
        }
        tokens.push(token);
    }
    if tokens.len() > 16 {
        return Err("auditInputs pointer exceeds 16 segments".into());
    }
    Ok(tokens)
}

fn validate_rules(
    rules: &[AuditInputRule],
    child: bool,
    count: &mut usize,
    keys: &mut BTreeSet<String>,
) -> Result<(), String> {
    let mut paths: Vec<Vec<String>> = Vec::new();
    for rule in rules {
        *count += 1;
        if *count > 64 {
            return Err("auditInputs exceeds 64 rules including children and omissions".into());
        }
        rule.validate_options()?;
        if !keys.insert(rule.key.clone()) {
            return Err("auditInputs contains duplicate action-local keys".into());
        }
        let path = parse_pointer(&rule.pointer)?;
        if paths
            .iter()
            .any(|other| path.starts_with(other) || other.starts_with(&path))
        {
            return Err("auditInputs contains duplicate or overlapping selectors".into());
        }
        paths.push(path);
        if let Some(fields) = &rule.fields {
            if child {
                return Err("auditInputs records cannot contain another records rule".into());
            }
            validate_rules(fields, true, count, keys)?;
        }
    }
    Ok(())
}

audit_enum! { /// Completeness of the retained requested facts.
    RequestAuditStatus { Complete, Partial, Unavailable }
}
audit_enum! { /// A captured value's fixed representation outcome.
    AuditValueState { Captured, Absent, Null, Invalid, TooLarge, Budget }
}
audit_enum! { /// Lossless JSON representation of an integer outside JavaScript's safe range.
    AuditValueEncoding { DecimalInteger }
}
audit_enum! { /// Fixed failure category with no dynamic request/error text.
    RequestAuditFailure { ProjectionFailed }
}

/// Self-contained version 1 audit snapshot, owned by the host.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestAudit {
    pub version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declaration_sha256: Option<String>,
    pub status: RequestAuditStatus,
    pub fields: Vec<RequestAuditField>,
    pub budget_omitted_fields: u64,
    pub absent_omitted_fields: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<RequestAuditFailure>,
}

/// Event-time presentation metadata; pointers and schemas are not retained.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFieldMetadata {
    pub key: String,
    pub label: String,
    pub display: AuditDisplay,
    pub role: AuditRole,
    pub kind: AuditValueKind,
    pub capture: AuditCapture,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<AuditValueShape>,
}

/// A selected top-level fact.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestAuditField {
    #[serde(flatten)]
    pub metadata: AuditFieldMetadata,
    #[serde(flatten)]
    pub data: AuditCapturedValue,
}

/// Value/status data shared by top-level fields and record cells.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditCapturedValue {
    pub state: AuditValueState,
    /// None means a malformed ancestor prevented determining presence.
    pub supplied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<AuditValueEncoding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<AuditValueItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub columns: Option<Vec<AuditFieldMetadata>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<AuditRecordRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limited_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_omitted_count: Option<u64>,
}

/// One of the first twenty source positions in a scalar list.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditValueItem {
    pub index: u64,
    pub state: AuditValueState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<AuditValueEncoding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_bytes: Option<u64>,
}

/// An atomic row with static child keys and its original input index.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecordRow {
    pub index: u64,
    pub state: AuditValueState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cells: Option<BTreeMap<String, AuditCapturedValue>>,
}

#[cfg(test)]
mod tests;
