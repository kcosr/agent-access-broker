//! Declared media-type policy for bounded native downloads.
//!
//! Declarations are not content detection: an upstream can mislabel bytes. A
//! generic declaration supplies no specific type, and parameters do not affect
//! the policy. Providers retain their original display values separately.

use crate::{ProviderError, ReasonCode};
use reqwest::header::{CONTENT_TYPE, HeaderMap};
use serde::Deserialize;

const GENERIC_MEDIA_TYPE: &str = "application/octet-stream";

/// One upstream media-type declaration, classified without retaining malformed
/// input. Construct it from a metadata string or the response headers; it does
/// not identify or inspect the file's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaTypeDeclaration {
    kind: DeclarationKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DeclarationKind {
    Unspecified,
    Concrete(String),
    Malformed,
}

impl MediaTypeDeclaration {
    /// Missing, null, empty, and generic declarations supply no specific type.
    pub const fn unspecified() -> Self {
        Self {
            kind: DeclarationKind::Unspecified,
        }
    }

    /// Mark a present declaration that cannot be interpreted as a media type,
    /// for example a non-string metadata member.
    pub const fn malformed() -> Self {
        Self {
            kind: DeclarationKind::Malformed,
        }
    }

    /// Classify a metadata string or one textual `Content-Type` value.
    ///
    /// Parameters after the first semicolon are ignored. Concrete type and
    /// subtype tokens must be ASCII and must not contain wildcards. An empty
    /// string or `application/octet-stream` is unspecified; other spellings,
    /// including `binary/octet-stream`, are concrete types.
    pub fn parse(value: &str) -> Self {
        if value.trim().is_empty() {
            return Self::unspecified();
        }
        let essence = value.split(';').next().unwrap_or_default().trim();
        let Some((major, minor)) = media_type_parts(essence) else {
            return Self::malformed();
        };
        if !concrete_token(major) || !concrete_token(minor) {
            return Self::malformed();
        }
        if essence.eq_ignore_ascii_case(GENERIC_MEDIA_TYPE) {
            return Self::unspecified();
        }
        Self {
            kind: DeclarationKind::Concrete(essence.to_ascii_lowercase()),
        }
    }

    /// Classify all response `Content-Type` fields. Absence is unspecified;
    /// duplicate fields or a non-textual value are malformed, even when one
    /// field happens to name a permitted type.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut values = headers.get_all(CONTENT_TYPE).iter();
        let Some(value) = values.next() else {
            return Self::unspecified();
        };
        if values.next().is_some() {
            return Self::malformed();
        }
        match value.to_str() {
            Ok(value) => Self::parse(value),
            Err(_) => Self::malformed(),
        }
    }
}

/// A native download's declared media-type policy.
///
/// Patterns are exact `type/subtype`, `type/*`, or `*/*`, compared without case.
/// Deny patterns override allow patterns. Omitting `allow` admits all types;
/// explicitly setting it to an empty list admits none. Omitting `deny` denies
/// no types. Parameters and other wildcard forms are invalid configuration.
///
/// Configuration schema is intentionally exhaustive: these public fields are
/// the documented keys of a table that rejects unknown keys, so adding one is
/// a configuration contract change every renderer and validator must handle.
/// Build it from [`Default`] with struct update syntax or deserialize it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MediaTypePolicyConfig {
    #[serde(default = "default_allow")]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

fn default_allow() -> Vec<String> {
    vec!["*/*".to_string()]
}

impl Default for MediaTypePolicyConfig {
    fn default() -> Self {
        Self {
            allow: default_allow(),
            deny: Vec::new(),
        }
    }
}

impl MediaTypePolicyConfig {
    /// Report invalid operator patterns using the full configuration-table
    /// label. Pattern values are never echoed into diagnostics.
    pub fn validate(&self, label: &str, errors: &mut Vec<String>) {
        for (field, patterns) in [("allow", &self.allow), ("deny", &self.deny)] {
            for (index, value) in patterns.iter().enumerate() {
                if MediaTypePattern::parse(value).is_none() {
                    errors.push(format!(
                        "{label}.{field}[{index}] must be an exact media type, type/*, or */* without parameters"
                    ));
                }
            }
        }
    }

    /// Check metadata after authorization and membership, before requesting
    /// content. An unspecified type defers its decision until response headers
    /// arrive, except for an empty allowlist or a universal deny.
    pub fn check_metadata(&self, metadata: &MediaTypeDeclaration) -> Result<(), ProviderError> {
        let policy = self.patterns()?;
        if policy.denies_all() {
            return Err(policy_denied());
        }
        match &metadata.kind {
            DeclarationKind::Unspecified => Ok(()),
            DeclarationKind::Concrete(value) => policy.check(value),
            DeclarationKind::Malformed if policy.universal() => Ok(()),
            DeclarationKind::Malformed => Err(malformed_denied()),
        }
    }

    /// Check metadata and response declarations before exposing download bytes.
    ///
    /// Every concrete declaration must pass. Generic declarations are ignored
    /// beside a concrete one; if neither is concrete, the policy is checked
    /// against `application/octet-stream`. A malformed declaration is admitted
    /// only by a universal policy (`*/*` allowed and no deny patterns).
    /// Concrete metadata and response declarations need not be equal.
    pub fn check_download(
        &self,
        metadata: &MediaTypeDeclaration,
        response: &MediaTypeDeclaration,
    ) -> Result<(), ProviderError> {
        let policy = self.patterns()?;
        if [&metadata.kind, &response.kind]
            .into_iter()
            .any(|kind| matches!(kind, DeclarationKind::Malformed))
        {
            return if policy.universal() {
                Ok(())
            } else {
                Err(malformed_denied())
            };
        }
        let mut concrete = false;
        for declaration in [metadata, response] {
            if let DeclarationKind::Concrete(value) = &declaration.kind {
                concrete = true;
                policy.check(value)?;
            }
        }
        if concrete {
            Ok(())
        } else {
            policy.check(GENERIC_MEDIA_TYPE)
        }
    }

    fn patterns(&self) -> Result<ParsedPolicy<'_>, ProviderError> {
        match (parse_patterns(&self.allow), parse_patterns(&self.deny)) {
            (Some(allow), Some(deny)) => Ok(ParsedPolicy { allow, deny }),
            _ => Err(ProviderError::deny(
                ReasonCode::AttachmentMediaTypeDenied,
                "download media type policy is invalid",
            )),
        }
    }
}

fn parse_patterns(values: &[String]) -> Option<Vec<MediaTypePattern<'_>>> {
    values
        .iter()
        .map(|value| MediaTypePattern::parse(value))
        .collect()
}

enum MediaTypePattern<'a> {
    Any,
    Family(&'a str),
    Exact(&'a str, &'a str),
}

impl<'a> MediaTypePattern<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        let (major, minor) = media_type_parts(value)?;
        match (major, minor) {
            ("*", "*") => Some(Self::Any),
            (_, "*") if concrete_token(major) => Some(Self::Family(major)),
            (_, _) if concrete_token(major) && concrete_token(minor) => {
                Some(Self::Exact(major, minor))
            }
            _ => None,
        }
    }

    fn matches(&self, value: &str) -> bool {
        let Some((major, minor)) = media_type_parts(value) else {
            return false;
        };
        match self {
            Self::Any => true,
            Self::Family(expected) => expected.eq_ignore_ascii_case(major),
            Self::Exact(expected_major, expected_minor) => {
                expected_major.eq_ignore_ascii_case(major)
                    && expected_minor.eq_ignore_ascii_case(minor)
            }
        }
    }
}

struct ParsedPolicy<'a> {
    allow: Vec<MediaTypePattern<'a>>,
    deny: Vec<MediaTypePattern<'a>>,
}

impl ParsedPolicy<'_> {
    fn universal(&self) -> bool {
        self.deny.is_empty()
            && self
                .allow
                .iter()
                .any(|pattern| matches!(pattern, MediaTypePattern::Any))
    }

    fn denies_all(&self) -> bool {
        self.allow.is_empty()
            || self
                .deny
                .iter()
                .any(|pattern| matches!(pattern, MediaTypePattern::Any))
    }

    fn check(&self, value: &str) -> Result<(), ProviderError> {
        if self.allow.iter().any(|pattern| pattern.matches(value))
            && !self.deny.iter().any(|pattern| pattern.matches(value))
        {
            Ok(())
        } else {
            Err(policy_denied())
        }
    }
}

fn media_type_parts(value: &str) -> Option<(&str, &str)> {
    value.split_once('/')
}

fn concrete_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn policy_denied() -> ProviderError {
    ProviderError::deny(
        ReasonCode::AttachmentMediaTypeDenied,
        "download media type is not allowed by the configured policy",
    )
}

fn malformed_denied() -> ProviderError {
    ProviderError::deny(
        ReasonCode::AttachmentMediaTypeDenied,
        "download media type declaration is malformed under the configured policy",
    )
}

#[cfg(test)]
mod tests;
