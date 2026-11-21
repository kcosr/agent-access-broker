//! Offline resource locations. Nothing in this module can contact Confluence.
use super::{is_space_key, modern_blog_tail_after_date};
use agent_access_provider::{
    LocationNormalizationError, LocationNormalizationRequest, NormalizedResourceLocation,
    ResourceContainer, ResourceSelector, ResourceSelectorProjection, ResourceType,
    ResourceTypeDescriptor, SubtreeSelectorDescriptor,
};
use url::{Host, Url};

/// Exact pages/blogs and page/folder subtrees on a pinned Confluence site.
pub static CONFLUENCE_CONTENT_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("confluence_content"),
    "Confluence content",
    "Confluence content locations",
    "https://example.atlassian.net/wiki/spaces/ENG/pages/12345",
    is_content_location,
    &[],
)
.with_supports_all(false)
.with_exact_validator(is_exact_content_location)
.with_subtree(SubtreeSelectorDescriptor::new(
    is_subtree_content_location,
    "Page or folder and descendants",
    "Current descendants",
    "https://example.atlassian.net/wiki/spaces/ENG/folder/67890",
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

    fn segment(self) -> &'static str {
        match self {
            Self::Space => "",
            Self::Page => "pages",
            Self::Folder => "folder",
            Self::Blog => "blog",
        }
    }
}

/// Authored coordinates only: this value does not prove existence or ancestry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalContentLocation {
    pub(crate) site_origin: String,
    pub(crate) space_key: String,
    pub(crate) kind: ContentLocationKind,
    pub(crate) id: Option<String>,
}

impl CanonicalContentLocation {
    pub(crate) fn value(&self) -> String {
        match &self.id {
            Some(id) => format!(
                "{}/wiki/spaces/{}/{}/{id}",
                self.site_origin,
                self.space_key,
                self.kind.segment()
            ),
            None => format!("{}/wiki/spaces/{}", self.site_origin, self.space_key),
        }
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

fn raw_url_checks(raw: &str) -> Result<(), LocationNormalizationError> {
    if raw
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return Err(invalid_url(
            "Location URL contains an unsupported character",
        ));
    }
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

fn parse_location(
    raw: &str,
    decorated: bool,
) -> Result<CanonicalContentLocation, LocationNormalizationError> {
    let (url, site_origin) = parsed_url(raw)?;
    let mut path = url.path();
    if decorated {
        path = path.strip_suffix('/').unwrap_or(path);
    }
    let segments = path.split('/').collect::<Vec<_>>();
    let ["", "wiki", "spaces", space_key, tail @ ..] = segments.as_slice() else {
        return Err(invalid_url(
            "Location URL must identify a Confluence space, page, folder or blog",
        ));
    };
    if !is_space_key(space_key) || space_key.contains('%') {
        return Err(invalid_url(
            "Location URL must contain a canonical space key",
        ));
    }
    let (kind, id) = match tail {
        [] => (ContentLocationKind::Space, None),
        ["overview"] if decorated => (ContentLocationKind::Space, None),
        ["pages", id] => (ContentLocationKind::Page, Some(*id)),
        ["pages", id, _title] if decorated => (ContentLocationKind::Page, Some(*id)),
        ["folder", id] => (ContentLocationKind::Folder, Some(*id)),
        ["blog", tail @ ..] => {
            let tail = if decorated {
                modern_blog_tail_after_date(tail)
                    .map_err(|_| invalid_url("Location URL has an invalid blog date"))?
            } else {
                tail
            };
            match tail {
                [id] => (ContentLocationKind::Blog, Some(*id)),
                [id, _title] if decorated => (ContentLocationKind::Blog, Some(*id)),
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
    let location = CanonicalContentLocation {
        site_origin,
        space_key: (*space_key).to_owned(),
        kind,
        id: id.map(str::to_owned),
    };
    if !decorated && location.value() != raw {
        return Err(invalid_url(
            "Content selector must use its exact canonical URL",
        ));
    }
    Ok(location)
}

pub(crate) fn parse_canonical_content_location(
    value: &str,
) -> Result<CanonicalContentLocation, LocationNormalizationError> {
    let location = parse_location(value, false)?;
    if location.kind == ContentLocationKind::Space {
        return Err(invalid_url(
            "Content selector must identify a page, folder or blog",
        ));
    }
    Ok(location)
}

pub(crate) fn parse_creation_parent_url(
    value: &str,
    tenant_host: &str,
) -> Result<CanonicalContentLocation, LocationNormalizationError> {
    let location = parse_location(value.trim(), true)?;
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
        vec![ResourceContainer::new(
            ResourceType::from_static("confluence_space"),
            location.space_key,
        )],
    ))
}

pub(crate) fn normalize_location(
    request: &LocationNormalizationRequest<'_>,
) -> Result<NormalizedResourceLocation, LocationNormalizationError> {
    let (declared, declared_origin) = parsed_url(request.declared_site())?;
    if !matches!(declared.path(), "" | "/")
        || declared_origin != request.declared_site().trim_end_matches('/')
    {
        return Err(LocationNormalizationError::new(
            "service",
            "Service must declare a canonical HTTPS site origin",
        ));
    }
    let mut location = parse_location(request.url().trim(), true)?;
    if location.site_origin != declared_origin {
        return Err(invalid_url(
            "Location URL host does not match the selected service",
        ));
    }
    if let Some(space_key) = request.space_key() {
        if !is_space_key(space_key) {
            return Err(LocationNormalizationError::new(
                "spaceKey",
                "Space key must use the canonical Confluence key grammar",
            ));
        }
        location.space_key = space_key.to_owned();
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
                value: location.value(),
            },
        ),
        (ContentLocationKind::Page | ContentLocationKind::Folder, "subtree") => (
            ResourceType::from_static("confluence_content"),
            ResourceSelector::Subtree {
                value: location.value(),
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
        location.space_key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SITE: &str = "https://example.atlassian.net";

    fn normalize(url: &str, coverage: &str) -> serde_json::Value {
        serde_json::to_value(
            normalize_location(&LocationNormalizationRequest::new(SITE, url, coverage)).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn every_location_kind_normalizes_offline_with_explicit_coverage() {
        for (path, coverage, kind, resource_type, expected) in [
            (
                "/wiki/spaces/ENG",
                "space",
                "space",
                "confluence_space",
                "ENG",
            ),
            (
                "/wiki/spaces/ENG/overview/",
                "space",
                "space",
                "confluence_space",
                "ENG",
            ),
            (
                "/wiki/spaces/ENG/pages/12345/Runbooks/",
                "exact",
                "page",
                "confluence_content",
                "https://example.atlassian.net/wiki/spaces/ENG/pages/12345",
            ),
            (
                "/wiki/spaces/ENG/pages/12345/",
                "subtree",
                "page",
                "confluence_content",
                "https://example.atlassian.net/wiki/spaces/ENG/pages/12345",
            ),
            (
                "/wiki/spaces/ENG/folder/67890/",
                "subtree",
                "folder",
                "confluence_content",
                "https://example.atlassian.net/wiki/spaces/ENG/folder/67890",
            ),
            (
                "/wiki/spaces/ENG/blog/54321/Release",
                "exact",
                "blog",
                "confluence_content",
                "https://example.atlassian.net/wiki/spaces/ENG/blog/54321",
            ),
            (
                "/wiki/spaces/ENG/blog/2026/11/20/54321/Release/",
                "exact",
                "blog",
                "confluence_content",
                "https://example.atlassian.net/wiki/spaces/ENG/blog/54321",
            ),
        ] {
            let result = normalize(&format!("{SITE}{path}"), coverage);
            assert_eq!(result["resourceType"], resource_type);
            assert_eq!(result["locationKind"], kind);
            assert_eq!(result["configuredSpaceKey"], "ENG");
            assert_eq!(result["verification"], "not_checked");
            assert_eq!(result["selector"]["value"], expected);
        }
    }

    #[test]
    fn normalized_identity_ignores_titles_and_dns_case_but_preserves_key_case() {
        let first = normalize(
            "https://EXAMPLE.atlassian.net/wiki/spaces/Eng/pages/123/A",
            "exact",
        );
        let second = normalize(
            "https://example.atlassian.net/wiki/spaces/Eng/pages/123/B",
            "exact",
        );
        assert_eq!(first, second);
        assert_eq!(first["configuredSpaceKey"], "Eng");
        assert_ne!(
            first,
            normalize(
                "https://example.atlassian.net/wiki/spaces/ENG/pages/123",
                "exact"
            )
        );
        for key in ["x", "1", "~account-id", "~user.name@example.com"] {
            let result = normalize(&format!("{SITE}/wiki/spaces/{key}/pages/1"), "exact");
            assert_eq!(result["configuredSpaceKey"], key);
        }
    }

    #[test]
    fn override_is_an_explicit_canonical_key_assertion() {
        let request = LocationNormalizationRequest::new(
            SITE,
            "https://example.atlassian.net/wiki/spaces/alias/folder/123",
            "subtree",
        )
        .with_space_key(Some("RealKey"));
        let result = serde_json::to_value(normalize_location(&request).unwrap()).unwrap();
        assert_eq!(result["configuredSpaceKey"], "RealKey");
        assert_eq!(
            result["selector"]["value"],
            "https://example.atlassian.net/wiki/spaces/RealKey/folder/123"
        );
        assert!(normalize_location(&request.with_space_key(Some("%45NG"))).is_err());
    }

    #[test]
    fn rejects_ambiguous_or_credential_bearing_urls_before_url_normalization() {
        for url in [
            "http://example.atlassian.net/wiki/spaces/ENG/pages/1",
            "https://elsewhere.atlassian.net/wiki/spaces/ENG/pages/1",
            "https://user:secret@example.atlassian.net/wiki/spaces/ENG/pages/1",
            "https://@example.atlassian.net/wiki/spaces/ENG/pages/1",
            "https://example.atlassian.net:443/wiki/spaces/ENG/pages/1",
            "https://127.0.0.1/wiki/spaces/ENG/pages/1",
            "https://example.atlassian.net/wiki/spaces/ENG/../ENG/pages/1",
            "https://example.atlassian.net/wiki/spaces/ENG/%2e%2e/ENG/pages/1",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/1/Title%2Fextra",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/1/Title%5cextra",
            "https://example.atlassian.net/wiki/spaces/%45NG/pages/1",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/01",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/0",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/123456789012345678901",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/1?",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/1#",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/1/a/b",
            "https://example.atlassian.net/wiki/spaces/ENG/folder/1/title",
            "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/13/20/1/title",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/1\\title",
            "https://example.atlassian.net/wiki/x/share",
        ] {
            assert!(
                normalize_location(&LocationNormalizationRequest::new(SITE, url, "exact")).is_err(),
                "{url}"
            );
        }
    }

    #[test]
    fn strict_selectors_reject_decoration_and_unsupported_coverage() {
        let page = "https://example.atlassian.net/wiki/spaces/ENG/pages/123";
        let folder = "https://example.atlassian.net/wiki/spaces/ENG/folder/123";
        let blog = "https://example.atlassian.net/wiki/spaces/ENG/blog/123";
        assert!(is_exact_content_location(page));
        assert!(is_subtree_content_location(page));
        assert!(is_subtree_content_location(folder));
        assert!(is_exact_content_location(blog));
        assert!(!is_exact_content_location(folder));
        assert!(!is_subtree_content_location(blog));
        for value in [
            format!("{page}/"),
            format!("{page}/title"),
            page.replace("example", "EXAMPLE"),
            page.replace("/ENG/", "/%45NG/"),
        ] {
            assert!(!is_exact_content_location(&value));
            assert!(!is_subtree_content_location(&value));
        }
        for (url, coverage) in [
            (folder, "exact"),
            (blog, "subtree"),
            (page, "space"),
            (page, "all"),
            (page, "namespace"),
        ] {
            assert!(
                normalize_location(&LocationNormalizationRequest::new(SITE, url, coverage))
                    .is_err()
            );
        }
        assert!(project_selector(&ResourceSelector::All).is_err());
    }

    #[test]
    fn authored_projection_has_only_pinned_identity_coordinates() {
        let value = "https://other.atlassian.net/wiki/spaces/Mixed/folder/123".to_string();
        assert!(is_subtree_content_location(&value));
        let projection =
            serde_json::to_value(project_selector(&ResourceSelector::Subtree { value }).unwrap())
                .unwrap();
        assert_eq!(
            projection,
            json!({
                "siteOrigin": "https://other.atlassian.net",
                "rootKind": "folder",
                "containers": [{"resourceType":"confluence_space","value":"Mixed"}]
            })
        );
    }
}
