//! Offline resource locations. Nothing in this module can contact Confluence.
use super::{is_space_key, modern_blog_tail_after_date};
use agent_access_provider::{
    LocationNormalizationError, LocationNormalizationRequest, NormalizedResourceLocation,
    ResourceSelector, ResourceSelectorProjection, ResourceType, ResourceTypeDescriptor,
    SubtreeSelectorDescriptor,
};
use url::{Host, Url};

/// Exact pages/blogs and page/folder subtrees on a pinned Confluence site.
pub static CONFLUENCE_CONTENT_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("confluence_content"),
    "Confluence content",
    "Confluence content locations",
    "https://example.atlassian.net/wiki/content/page/12345",
    is_content_location,
    &[],
)
.with_supports_all(false)
.with_exact_validator(is_exact_content_location)
.with_subtree(SubtreeSelectorDescriptor::new(
    is_subtree_content_location,
    "Page or folder and descendants",
    "Current descendants",
    "https://example.atlassian.net/wiki/content/folder/67890",
))
.with_selector_projection(project_selector)
.with_location_normalizer(normalize_location);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContentLocationKind {
    Space,
    Page,
    Folder,
    Blog,
}

impl ContentLocationKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Space => "space",
            Self::Page => "page",
            Self::Folder => "folder",
            Self::Blog => "blog",
        }
    }
}

/// Stable authored identity, independent of observed content placement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalContentLocation {
    pub(crate) site_origin: String,
    pub(crate) kind: ContentLocationKind,
    pub(crate) id: Option<String>,
}

impl CanonicalContentLocation {
    pub(crate) fn value(&self) -> String {
        format!(
            "{}/wiki/content/{}/{}",
            self.site_origin,
            self.kind.as_str(),
            self.id
                .as_deref()
                .expect("canonical content has an immutable ID")
        )
    }
}

/// A browser locator keeps its route segment only for action URL consistency.
/// Resource normalization discards that segment for every content identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BrowserContentLocation {
    pub(crate) site_origin: String,
    pub(crate) space_key: String,
    pub(crate) kind: ContentLocationKind,
    pub(crate) id: Option<String>,
}

impl BrowserContentLocation {
    fn content_value(&self) -> String {
        CanonicalContentLocation {
            site_origin: self.site_origin.clone(),
            kind: self.kind,
            id: self.id.clone(),
        }
        .value()
    }
}

fn invalid_url(message: &'static str) -> LocationNormalizationError {
    LocationNormalizationError::new("url", message)
}

fn valid_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn raw_url_character_checks(raw: &str) -> Result<(), LocationNormalizationError> {
    if raw
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return Err(invalid_url(
            "Location URL contains an unsupported character",
        ));
    }
    Ok(())
}

fn raw_url_checks(raw: &str) -> Result<(), LocationNormalizationError> {
    raw_url_character_checks(raw)?;
    let Some((scheme, rest)) = raw.split_once("://") else {
        return Err(invalid_url("Location URL must use HTTPS"));
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid_url("Location URL must use HTTPS"));
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains(['@', ':', '[', ']', '%']) {
        return Err(invalid_url(
            "Location URL must use a DNS host without credentials or a port",
        ));
    }
    let path = &rest[authority_end..];
    let path = path.split(['?', '#']).next().unwrap_or_default();
    for segment in path.split('/') {
        let mut decoded = Vec::with_capacity(segment.len());
        let mut bytes = segment.bytes();
        while let Some(byte) = bytes.next() {
            if byte != b'%' {
                decoded.push(byte);
                continue;
            }
            let hex = |byte: u8| (byte as char).to_digit(16).map(|value| value as u8);
            let (Some(high), Some(low)) = (bytes.next().and_then(hex), bytes.next().and_then(hex))
            else {
                return Err(invalid_url("Location URL has invalid path encoding"));
            };
            let value = high * 16 + low;
            if value.is_ascii_control() || matches!(value, b'/' | b'\\' | b'?' | b'#') {
                return Err(invalid_url(
                    "Location URL must not contain encoded path delimiters",
                ));
            }
            decoded.push(value);
        }
        if matches!(decoded.as_slice(), b"." | b"..") {
            return Err(invalid_url("Location URL must not contain dot segments"));
        }
    }
    Ok(())
}

fn parsed_url(raw: &str) -> Result<(Url, String), LocationNormalizationError> {
    raw_url_checks(raw)?;
    let url = Url::parse(raw).map_err(|_| invalid_url("Location URL is invalid"))?;
    if url.query().is_some() {
        return Err(invalid_url(
            "Location URL must not include query parameters",
        ));
    }
    if url.fragment().is_some() {
        return Err(invalid_url("Location URL must not include a fragment"));
    }
    let Some(Host::Domain(host)) = url.host() else {
        return Err(invalid_url("Location URL must use a DNS host"));
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if !valid_dns_name(host) {
        return Err(invalid_url("Location URL must use a valid DNS host"));
    }
    let site_origin = format!("https://{host}");
    Ok((url, site_origin))
}

pub(crate) fn is_canonical_content_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_browser_location(raw: &str) -> Result<BrowserContentLocation, LocationNormalizationError> {
    raw_url_character_checks(raw)?;
    let (url, site_origin) = parsed_url(raw.trim())?;
    let path = url.path().strip_suffix('/').unwrap_or(url.path());
    let segments = path.split('/').collect::<Vec<_>>();
    let ["", "wiki", "spaces", space_key, tail @ ..] = segments.as_slice() else {
        return Err(invalid_url(
            "Location URL must identify a Confluence space, page, folder or blog",
        ));
    };
    // The grammar bounds an inert routing segment. It does not establish current
    // space membership or resolve an alias to a canonical key.
    if !is_space_key(space_key) || space_key.contains('%') {
        return Err(invalid_url(
            "Location URL must contain a supported space key or alias segment",
        ));
    }
    let (kind, id) = match tail {
        [] | ["overview"] => (ContentLocationKind::Space, None),
        ["pages", id] | ["pages", id, _] => (ContentLocationKind::Page, Some(*id)),
        ["folder", id] => (ContentLocationKind::Folder, Some(*id)),
        ["blog", tail @ ..] => {
            let tail = modern_blog_tail_after_date(tail)
                .map_err(|_| invalid_url("Location URL has an invalid blog date"))?;
            match tail {
                [id] | [id, _] => (ContentLocationKind::Blog, Some(*id)),
                _ => return Err(invalid_url("Location URL has an unsupported blog path")),
            }
        }
        _ => return Err(invalid_url("Location URL has an unsupported path")),
    };
    if id.is_some_and(|id| !is_canonical_content_id(id)) {
        return Err(invalid_url(
            "Location URL content ID must be a nonzero decimal value of at most 20 digits",
        ));
    }
    Ok(BrowserContentLocation {
        site_origin,
        space_key: (*space_key).to_owned(),
        kind,
        id: id.map(str::to_owned),
    })
}

pub(crate) fn parse_canonical_content_location(
    value: &str,
) -> Result<CanonicalContentLocation, LocationNormalizationError> {
    let (url, site_origin) = parsed_url(value)?;
    let segments = url.path().split('/').collect::<Vec<_>>();
    let ["", "wiki", "content", kind, id] = segments.as_slice() else {
        return Err(invalid_url(
            "Content selector must identify a canonical page, folder or blog",
        ));
    };
    let kind = match *kind {
        "page" => ContentLocationKind::Page,
        "folder" => ContentLocationKind::Folder,
        "blog" => ContentLocationKind::Blog,
        _ => return Err(invalid_url("Content selector kind is unsupported")),
    };
    if !is_canonical_content_id(id) {
        return Err(invalid_url(
            "Content selector ID must be a nonzero decimal value of at most 20 digits",
        ));
    }
    let location = CanonicalContentLocation {
        site_origin,
        kind,
        id: Some((*id).to_owned()),
    };
    if location.value() != value {
        return Err(invalid_url(
            "Content selector must use its exact canonical identity",
        ));
    }
    Ok(location)
}

pub(crate) fn parse_creation_parent_url(
    value: &str,
    tenant_host: &str,
) -> Result<BrowserContentLocation, LocationNormalizationError> {
    let location = parse_browser_location(value.trim())?;
    if location.site_origin != format!("https://{tenant_host}")
        || !matches!(
            location.kind,
            ContentLocationKind::Page | ContentLocationKind::Folder
        )
    {
        return Err(invalid_url(
            "Parent URL must identify a page or folder on the configured site",
        ));
    }
    Ok(location)
}

fn is_exact_content_location(value: &str) -> bool {
    parse_canonical_content_location(value).is_ok_and(|location| {
        matches!(
            location.kind,
            ContentLocationKind::Page | ContentLocationKind::Blog
        )
    })
}

fn is_content_location(value: &str) -> bool {
    parse_canonical_content_location(value).is_ok()
}

fn is_subtree_content_location(value: &str) -> bool {
    parse_canonical_content_location(value).is_ok_and(|location| {
        matches!(
            location.kind,
            ContentLocationKind::Page | ContentLocationKind::Folder
        )
    })
}

fn project_selector(
    selector: &ResourceSelector,
) -> Result<ResourceSelectorProjection, LocationNormalizationError> {
    let (value, allowed) = match selector {
        ResourceSelector::Exact { value } => (value, is_exact_content_location(value)),
        ResourceSelector::Subtree { value } => (value, is_subtree_content_location(value)),
        _ => {
            return Err(LocationNormalizationError::new(
                "selector",
                "Content selectors support exact pages/blogs or page/folder subtrees",
            ));
        }
    };
    if !allowed {
        return Err(LocationNormalizationError::new(
            "selector",
            "Content selector has an unsupported kind or noncanonical value",
        ));
    }
    let location = parse_canonical_content_location(value)?;
    Ok(ResourceSelectorProjection::new(
        location.site_origin,
        location.kind.as_str(),
    ))
}

pub(crate) fn normalize_location(
    request: &LocationNormalizationRequest<'_>,
) -> Result<NormalizedResourceLocation, LocationNormalizationError> {
    let (declared, declared_origin) = parsed_url(request.declared_site()).map_err(|_| {
        LocationNormalizationError::new(
            "service",
            "Service must declare a canonical HTTPS site origin",
        )
    })?;
    if !matches!(declared.path(), "" | "/")
        || declared_origin != request.declared_site().trim_end_matches('/')
    {
        return Err(LocationNormalizationError::new(
            "service",
            "Service must declare a canonical HTTPS site origin",
        ));
    }
    let location = parse_browser_location(request.url())?;
    if location.site_origin != declared_origin {
        return Err(invalid_url(
            "Location URL host does not match the selected service",
        ));
    }
    let (resource_type, selector) = match (location.kind, request.coverage()) {
        (ContentLocationKind::Space, "space") => (
            ResourceType::from_static("confluence_space"),
            ResourceSelector::Exact {
                value: location.space_key.clone(),
            },
        ),
        (ContentLocationKind::Page | ContentLocationKind::Blog, "exact") => (
            ResourceType::from_static("confluence_content"),
            ResourceSelector::Exact {
                value: location.content_value(),
            },
        ),
        (ContentLocationKind::Page | ContentLocationKind::Folder, "subtree") => (
            ResourceType::from_static("confluence_content"),
            ResourceSelector::Subtree {
                value: location.content_value(),
            },
        ),
        _ => {
            return Err(LocationNormalizationError::new(
                "coverage",
                "Coverage is not supported for this location kind",
            ));
        }
    };
    Ok(NormalizedResourceLocation::new(
        resource_type,
        selector,
        location.kind.as_str(),
    ))
}

#[cfg(test)]
mod tests;
