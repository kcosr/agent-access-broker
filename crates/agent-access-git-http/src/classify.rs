use crate::config::GitConfig;
use agent_access_provider::{ProviderError, ReasonCode, ResourceScopes};
use http::header::{CONTENT_ENCODING, CONTENT_TYPE, TRAILER};
use http::{HeaderMap, Method, Uri};
use percent_encoding::percent_decode_str;
use url::form_urlencoded;

pub(crate) struct ClassifiedRequest {
    pub(crate) git_request_kind: GitRequestKind,
    pub(crate) resource_scopes: ResourceScopes,
}

#[derive(Debug)]
struct GatewayClassifyError {
    code: ReasonCode,
    reason: &'static str,
}

impl GatewayClassifyError {
    fn new(code: ReasonCode, reason: &'static str) -> Self {
        Self { code, reason }
    }

    fn rule_not_found(reason: &'static str) -> Self {
        Self::new(ReasonCode::GatewayRuleNotFound, reason)
    }

    fn method_denied(reason: &'static str) -> Self {
        Self::new(ReasonCode::GatewayMethodDenied, reason)
    }

    fn query_denied(reason: &'static str) -> Self {
        Self::new(ReasonCode::GatewayQueryDenied, reason)
    }

    fn git_service_denied(reason: &'static str) -> Self {
        Self::new(ReasonCode::GitServiceDenied, reason)
    }

    fn provider_error(&self) -> ProviderError {
        ProviderError::deny(self.code, self.reason)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GitRequestKind {
    UploadPackDiscovery,
    UploadPackPost,
    ReceivePackDiscovery,
    ReceivePackPost,
}

impl GitRequestKind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::UploadPackDiscovery => "upload-pack-discovery",
            Self::UploadPackPost => "upload-pack-post",
            Self::ReceivePackDiscovery => "receive-pack-discovery",
            Self::ReceivePackPost => "receive-pack-post",
        }
    }

    pub(crate) fn relative_target(self, scopes: &ResourceScopes) -> Result<String, ProviderError> {
        let repository = scopes
            .get("repository")
            .and_then(|repositories| match repositories.as_slice() {
                [repository] if agent_access_provider::is_canonical_repository_path(repository) => {
                    Some(repository)
                }
                _ => None,
            })
            .ok_or_else(|| {
                ProviderError::error(
                    ReasonCode::GatewayUpstreamDenied,
                    "gateway authorized repository is invalid",
                )
            })?;
        let suffix = match self {
            Self::UploadPackDiscovery => "info/refs?service=git-upload-pack",
            Self::ReceivePackDiscovery => "info/refs?service=git-receive-pack",
            Self::UploadPackPost => "git-upload-pack",
            Self::ReceivePackPost => "git-receive-pack",
        };
        // The URL writer applies the same percent encoding as forwarding did
        // before extraction, including canonical Unicode repository names.
        let mut relative = url::Url::parse("https://gateway.invalid/").expect("literal base URL");
        let (path, query) = suffix
            .split_once('?')
            .map_or((suffix, None), |(path, query)| (path, Some(query)));
        relative.set_path(&format!("/{repository}.git/{path}"));
        relative.set_query(query);
        Ok(relative[url::Position::BeforePath..].to_string())
    }

    pub(crate) fn method(self) -> Method {
        if self.is_pack_post() {
            Method::POST
        } else {
            Method::GET
        }
    }

    pub(crate) fn action(self) -> &'static str {
        match self {
            Self::UploadPackDiscovery | Self::UploadPackPost => "repo.fetch",
            Self::ReceivePackDiscovery | Self::ReceivePackPost => "repo.push",
        }
    }

    pub(crate) fn is_upload_pack_post(self) -> bool {
        matches!(self, Self::UploadPackPost)
    }

    /// `git-upload-pack` and `git-receive-pack` POSTs, the counted invocations.
    pub(crate) fn is_pack_post(self) -> bool {
        matches!(self, Self::UploadPackPost | Self::ReceivePackPost)
    }

    pub(crate) fn is_receive_pack_post(self) -> bool {
        matches!(self, Self::ReceivePackPost)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GitContentEncoding {
    Gzip,
}

impl GitContentEncoding {
    pub(crate) fn header_value(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
        }
    }
}

pub(crate) fn classify(
    git: &GitConfig,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<ClassifiedRequest, ProviderError> {
    classify_inner(git, method, uri, headers).map_err(|error| error.provider_error())
}

fn classify_inner(
    git: &GitConfig,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<ClassifiedRequest, GatewayClassifyError> {
    let (git_request_kind, repository) = match *method {
        Method::GET => {
            validate_git_protocol_header(headers)?;
            classify_git_discovery(uri, git.allow_fetch, git.allow_push)?
        }
        Method::POST => {
            validate_git_protocol_header(headers)?;
            classify_git_post(uri, headers, git.allow_fetch, git.allow_push)?
        }
        _ => {
            return Err(GatewayClassifyError::method_denied(
                "gateway method is not supported",
            ));
        }
    };
    Ok(ClassifiedRequest {
        git_request_kind,
        resource_scopes: ResourceScopes::from([("repository".to_string(), vec![repository])]),
    })
}

fn classify_git_discovery(
    uri: &Uri,
    allow_fetch: bool,
    allow_push: bool,
) -> Result<(GitRequestKind, String), GatewayClassifyError> {
    let repository = repository_from_suffix(uri.path(), &["info", "refs"])?;
    let mut pairs = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes());
    let Some((key, value)) = pairs.next() else {
        return Err(GatewayClassifyError::query_denied(
            "git discovery query is required",
        ));
    };
    if pairs.next().is_some() || key != "service" {
        return Err(GatewayClassifyError::query_denied(
            "git discovery query is invalid",
        ));
    }
    match value.as_ref() {
        "git-upload-pack" if allow_fetch => Ok((GitRequestKind::UploadPackDiscovery, repository)),
        "git-receive-pack" if allow_push => Ok((GitRequestKind::ReceivePackDiscovery, repository)),
        _ => Err(GatewayClassifyError::git_service_denied(
            "git discovery service is not allowed",
        )),
    }
}

fn classify_git_post(
    uri: &Uri,
    headers: &HeaderMap,
    allow_fetch: bool,
    allow_push: bool,
) -> Result<(GitRequestKind, String), GatewayClassifyError> {
    if uri.query().is_some() {
        return Err(GatewayClassifyError::query_denied(
            "git POST query is not supported",
        ));
    }
    if let Ok(repository) = repository_from_suffix(uri.path(), &["git-upload-pack"]) {
        if !allow_fetch {
            return Err(GatewayClassifyError::git_service_denied(
                "git fetch is not allowed",
            ));
        }
        validate_git_content_type(headers, "application/x-git-upload-pack-request")?;
        return Ok((GitRequestKind::UploadPackPost, repository));
    }
    if let Ok(repository) = repository_from_suffix(uri.path(), &["git-receive-pack"]) {
        if !allow_push {
            return Err(GatewayClassifyError::git_service_denied(
                "git push is not allowed",
            ));
        }
        validate_git_content_type(headers, "application/x-git-receive-pack-request")?;
        return Ok((GitRequestKind::ReceivePackPost, repository));
    }
    Err(GatewayClassifyError::rule_not_found(
        "git POST route is not allowed",
    ))
}

fn validate_git_protocol_header(headers: &HeaderMap) -> Result<(), GatewayClassifyError> {
    let mut values = headers.get_all("Git-Protocol").iter();
    let Some(raw) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(GatewayClassifyError::new(
            ReasonCode::GatewayHeaderDenied,
            "Git-Protocol header is ambiguous",
        ));
    }
    let value = raw.to_str().map_err(|_| {
        GatewayClassifyError::new(ReasonCode::GatewayHeaderDenied, "Git-Protocol is invalid")
    })?;
    if value != "version=2" {
        return Err(GatewayClassifyError::new(
            ReasonCode::GatewayHeaderDenied,
            "Git-Protocol is not allowed",
        ));
    }
    Ok(())
}

fn validate_git_content_type(
    headers: &HeaderMap,
    expected: &'static str,
) -> Result<(), GatewayClassifyError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(raw) = values.next() else {
        return Err(GatewayClassifyError::new(
            ReasonCode::GatewayContentTypeDenied,
            "Git POST content type is required",
        ));
    };
    if values.next().is_some() {
        return Err(GatewayClassifyError::new(
            ReasonCode::GatewayContentTypeDenied,
            "Git POST content type is ambiguous",
        ));
    }
    let value = raw.to_str().map_err(|_| {
        GatewayClassifyError::new(
            ReasonCode::GatewayContentTypeDenied,
            "Git POST content type is invalid",
        )
    })?;
    if !value.eq_ignore_ascii_case(expected) {
        return Err(GatewayClassifyError::new(
            ReasonCode::GatewayContentTypeDenied,
            "Git POST content type is not allowed",
        ));
    }
    Ok(())
}

fn repository_from_suffix(path: &str, suffix: &[&str]) -> Result<String, GatewayClassifyError> {
    let segments = decoded_path_segments(path)?;
    if segments.len() <= suffix.len() {
        return Err(GatewayClassifyError::rule_not_found(
            "repository path is missing",
        ));
    }
    if !segments
        .iter()
        .rev()
        .zip(suffix.iter().rev())
        .take(suffix.len())
        .all(|(segment, expected)| segment == expected)
    {
        return Err(GatewayClassifyError::rule_not_found(
            "gateway route is not supported",
        ));
    }
    let mut repository_segments = segments[..segments.len() - suffix.len()].to_vec();
    if repository_segments[..repository_segments.len().saturating_sub(1)]
        .iter()
        .any(|segment| segment.ends_with(".git"))
    {
        return Err(GatewayClassifyError::rule_not_found(
            "repository path has ambiguous .git segment",
        ));
    }
    let Some(last) = repository_segments.last_mut() else {
        return Err(GatewayClassifyError::rule_not_found(
            "repository path is missing",
        ));
    };
    if let Some(stripped) = last.strip_suffix(".git") {
        *last = stripped.to_string();
    }
    let repository = repository_segments.join("/");
    // Classify with the same canonical grammar policy authorizes, so a path
    // no grant could ever match is rejected here rather than after lookup.
    if !agent_access_provider::is_canonical_repository_path(&repository) {
        return Err(GatewayClassifyError::rule_not_found(
            "repository path is invalid",
        ));
    }
    Ok(repository)
}

fn decoded_path_segments(path: &str) -> Result<Vec<String>, GatewayClassifyError> {
    if !path.starts_with('/') {
        return Err(GatewayClassifyError::rule_not_found(
            "gateway path is invalid",
        ));
    }
    path.split('/')
        .skip(1)
        .map(|segment| {
            let decoded = percent_decode_str(segment)
                .decode_utf8()
                .map_err(|_| GatewayClassifyError::rule_not_found("gateway path is invalid"))?
                .into_owned();
            if decoded.contains('/')
                || decoded.contains('\\')
                || decoded.chars().any(char::is_control)
            {
                return Err(GatewayClassifyError::rule_not_found(
                    "gateway path is invalid",
                ));
            }
            Ok(decoded)
        })
        .collect()
}

pub(crate) fn validate_representation_headers(
    headers: &HeaderMap,
    kind: GitRequestKind,
) -> Result<Option<GitContentEncoding>, ProviderError> {
    if headers.contains_key(TRAILER) {
        return Err(gateway_header_denied(
            "Git gateway Trailer header is not allowed",
        ));
    }

    let mut values = headers.get_all(CONTENT_ENCODING).iter();
    let Some(raw) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(gateway_header_denied(
            "Git Content-Encoding header is ambiguous",
        ));
    }
    let value = raw
        .to_str()
        .map_err(|_| gateway_header_denied("Git Content-Encoding is invalid"))?
        .trim();
    if !value.eq_ignore_ascii_case("gzip") {
        return Err(gateway_header_denied("Git Content-Encoding is not allowed"));
    }
    if kind.is_upload_pack_post() {
        return Ok(Some(GitContentEncoding::Gzip));
    }
    if kind.is_receive_pack_post() {
        return Err(gateway_header_denied(
            "Git receive-pack Content-Encoding is not supported",
        ));
    }
    Err(gateway_header_denied(
        "Git discovery Content-Encoding is not supported",
    ))
}

fn gateway_header_denied(message: &'static str) -> ProviderError {
    ProviderError::deny(ReasonCode::GatewayHeaderDenied, message)
}

pub(crate) fn request_headers(
    source: &HeaderMap,
    kind: GitRequestKind,
    content_encoding: Option<GitContentEncoding>,
) -> Result<HeaderMap, ProviderError> {
    let mut selected = HeaderMap::new();
    for name in ["Accept", "User-Agent", "Git-Protocol"] {
        select_header(source, &mut selected, name)?;
    }
    if kind.is_pack_post() {
        select_header(source, &mut selected, "Content-Type")?;
    }
    if let Some(encoding) = content_encoding {
        selected.insert(
            CONTENT_ENCODING,
            http::HeaderValue::from_static(encoding.header_value()),
        );
    }
    Ok(selected)
}

fn select_header(
    source: &HeaderMap,
    target: &mut HeaderMap,
    name: &str,
) -> Result<(), ProviderError> {
    let mut values = source.get_all(name).iter();
    let Some(raw) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(ProviderError::deny(
            ReasonCode::GatewayHeaderDenied,
            format!("gateway request header {name} is ambiguous"),
        ));
    }
    raw.to_str().map_err(|_| {
        ProviderError::deny(
            ReasonCode::GatewayHeaderDenied,
            format!("gateway request header {name} is invalid"),
        )
    })?;
    let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::GatewayHeaderDenied,
            "gateway request header name is invalid",
        )
    })?;
    target.insert(name, raw.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git() -> GitConfig {
        toml::from_str("allow_fetch = true\nallow_push = true").unwrap()
    }

    #[test]
    fn canonical_routes_preserve_action_scopes_and_transport_suffix() {
        for (input, repository, encoded) in [
            ("team/project", "team/project", "team/project"),
            ("team/project.git", "team/project", "team/project"),
            ("team/proj%65ct%2Egit", "team/project", "team/project"),
            ("t%C3%A9am/project", "téam/project", "t%C3%A9am/project"),
            (
                "team/project.git.git",
                "team/project.git",
                "team/project.git",
            ),
        ] {
            for (method, suffix, content_type, kind) in [
                (
                    Method::GET,
                    "info/refs?service=git-upload-pack",
                    None,
                    GitRequestKind::UploadPackDiscovery,
                ),
                (
                    Method::GET,
                    "info/refs?service=git-receive-pack",
                    None,
                    GitRequestKind::ReceivePackDiscovery,
                ),
                (
                    Method::POST,
                    "git-upload-pack",
                    Some("application/x-git-upload-pack-request"),
                    GitRequestKind::UploadPackPost,
                ),
                (
                    Method::POST,
                    "git-receive-pack",
                    Some("application/x-git-receive-pack-request"),
                    GitRequestKind::ReceivePackPost,
                ),
            ] {
                let mut headers = HeaderMap::new();
                if let Some(value) = content_type {
                    headers.insert(CONTENT_TYPE, http::HeaderValue::from_static(value));
                }
                let uri: Uri = format!("/{input}/{suffix}").parse().unwrap();
                let classified = classify(&git(), &method, &uri, &headers).unwrap();
                assert_eq!(classified.git_request_kind, kind);
                assert_eq!(classified.resource_scopes["repository"], [repository]);
                assert_eq!(
                    kind.relative_target(&classified.resource_scopes).unwrap(),
                    format!("/{encoded}.git/{suffix}")
                );
            }
        }
    }

    #[test]
    fn malformed_and_undeclared_routes_are_not_reclassified() {
        for uri in [
            "/project/info/refs?service=git-upload-pack",
            "/team/project.git/../other/info/refs?service=git-upload-pack",
            "/team%2Fother/project/info/refs?service=git-upload-pack",
            "/team/project/info/refs?service=git-upload-pack&service=git-receive-pack",
            "/team/project/info/refs?service=unknown",
            "/team/project/info/refs",
        ] {
            assert!(
                classify(
                    &git(),
                    &Method::GET,
                    &uri.parse().unwrap(),
                    &HeaderMap::new()
                )
                .is_err(),
                "{uri}"
            );
        }
        let error = classify(
            &git(),
            &Method::HEAD,
            &"/team/project/info/refs?service=git-upload-pack"
                .parse()
                .unwrap(),
            &HeaderMap::new(),
        )
        .err()
        .unwrap();
        assert_eq!(error.reason_code(), ReasonCode::GatewayMethodDenied);
    }

    #[test]
    fn gzip_is_only_an_upload_pack_representation() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, http::HeaderValue::from_static("gzip"));
        assert!(
            validate_representation_headers(&headers, GitRequestKind::UploadPackPost)
                .unwrap()
                .is_some()
        );
        for kind in [
            GitRequestKind::UploadPackDiscovery,
            GitRequestKind::ReceivePackDiscovery,
            GitRequestKind::ReceivePackPost,
        ] {
            assert_eq!(
                validate_representation_headers(&headers, kind)
                    .err()
                    .unwrap()
                    .reason_code(),
                ReasonCode::GatewayHeaderDenied
            );
        }
        headers.append(CONTENT_ENCODING, http::HeaderValue::from_static("gzip"));
        assert!(validate_representation_headers(&headers, GitRequestKind::UploadPackPost).is_err());
    }

    #[test]
    fn selected_headers_never_forward_identity_and_ambiguity_fails() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("authorization", "secret"),
            ("cookie", "secret"),
            ("x-aw-identity-token-sha256", "secret"),
            ("accept", "*/*"),
            ("user-agent", "git/test"),
        ] {
            headers.insert(
                http::HeaderName::from_static(name),
                http::HeaderValue::from_static(value),
            );
        }
        let selected =
            request_headers(&headers, GitRequestKind::UploadPackDiscovery, None).unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected["accept"], "*/*");
        headers.append("accept", http::HeaderValue::from_static("other"));
        let error =
            request_headers(&headers, GitRequestKind::UploadPackDiscovery, None).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::GatewayHeaderDenied);
        assert_eq!(error.message, "gateway request header Accept is ambiguous");
    }
}

#[cfg(test)]
mod parity_tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn gateway_upstream_target_requires_one_canonical_authorized_repository() {
        for repositories in [
            vec![],
            vec!["team/project", "other/project"],
            vec!["project"],
            vec!["team/../project"],
            vec!["team/project%2Fother"],
        ] {
            let scopes = ResourceScopes::from([(
                "repository".to_string(),
                repositories.into_iter().map(str::to_string).collect(),
            )]);
            let error = GitRequestKind::UploadPackDiscovery
                .relative_target(&scopes)
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::GatewayUpstreamDenied);
        }
        assert!(
            GitRequestKind::UploadPackDiscovery
                .relative_target(&ResourceScopes::new())
                .is_err()
        );
    }

    #[test]
    fn gateway_git_url_normalization_keeps_invalid_paths_and_queries_rejected() {
        let git: GitConfig = toml::from_str("allow_fetch = true\nallow_push = true").unwrap();
        for repository in [
            "project",
            "team//project",
            "team/.git",
            "team.git/project",
            "team%2Egit/project",
            "team/../project",
            "team/%2E%2E/project",
            "team/project%2Fother",
            "team/project%5Cother",
            "team/project%25other",
            "team/project%3Fother",
            "team/project%23other",
            "team/project%00",
            "team/project%FF",
            "team/project%ZZ",
        ] {
            for service in ["git-upload-pack", "git-receive-pack"] {
                let uri = format!("/{repository}/info/refs?service={service}")
                    .parse()
                    .unwrap();
                assert!(
                    classify(&git, &Method::GET, &uri, &HeaderMap::new()).is_err(),
                    "{uri}"
                );
                let uri = format!("/{repository}/{service}").parse().unwrap();
                let mut headers = HeaderMap::new();
                headers.insert(
                    CONTENT_TYPE,
                    format!("application/x-{service}-request").parse().unwrap(),
                );
                assert!(
                    classify(&git, &Method::POST, &uri, &headers).is_err(),
                    "{uri}"
                );
            }
        }
        for query in [
            "",
            "?service=other",
            "?service=git-upload-pack&service=git-receive-pack",
            "?service=git-upload-pack&extra=value",
        ] {
            let uri = format!("/team/project/info/refs{query}").parse().unwrap();
            assert!(
                classify(&git, &Method::GET, &uri, &HeaderMap::new()).is_err(),
                "{uri}"
            );
        }
        let uri = "/team/project/git-upload-pack?service=git-upload-pack"
            .parse()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-git-upload-pack-request"),
        );
        let error = classify(&git, &Method::POST, &uri, &headers).err().unwrap();
        assert_eq!(error.reason_code(), ReasonCode::GatewayQueryDenied);
    }

    #[test]
    fn gateway_repository_paths_canonicalize_safe_percent_encoding() {
        let repository =
            repository_from_suffix("/sip%65/service.git/info/refs", &["info", "refs"]).unwrap();
        assert_eq!(repository, "sipe/service");

        let error =
            repository_from_suffix("/sip%2Fservice.git/info/refs", &["info", "refs"]).unwrap_err();
        assert_eq!(error.code, ReasonCode::GatewayRuleNotFound);

        let error =
            repository_from_suffix("/sip%25/service.git/info/refs", &["info", "refs"]).unwrap_err();
        assert_eq!(error.code, ReasonCode::GatewayRuleNotFound);
    }

    #[test]
    fn gateway_repository_paths_follow_the_canonical_repository_grammar() {
        // No grant can match a single-segment path, so classification rejects
        // it before policy lookup instead of denying it later.
        for path in ["/service.git/info/refs", "/12345.git/info/refs"] {
            let error = repository_from_suffix(path, &["info", "refs"]).unwrap_err();
            assert_eq!(error.code, ReasonCode::GatewayRuleNotFound, "{path}");
            assert_eq!(error.reason, "repository path is invalid", "{path}");
        }
        assert_eq!(
            repository_from_suffix("/team/12345.git/info/refs", &["info", "refs"]).unwrap(),
            "team/12345"
        );
    }

    #[test]
    fn git_gateway_representation_header_validation_is_action_scoped() {
        let mut upload_pack_headers = HeaderMap::new();
        upload_pack_headers.insert(CONTENT_ENCODING, HeaderValue::from_static(" GZIP "));
        assert_eq!(
            validate_representation_headers(&upload_pack_headers, GitRequestKind::UploadPackPost,)
                .unwrap(),
            Some(GitContentEncoding::Gzip)
        );

        let mut duplicate_encoding = HeaderMap::new();
        duplicate_encoding.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        duplicate_encoding.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        let duplicate_error =
            validate_representation_headers(&duplicate_encoding, GitRequestKind::UploadPackPost)
                .unwrap_err();
        assert_eq!(
            duplicate_error.reason_code(),
            ReasonCode::GatewayHeaderDenied
        );

        let mut unsupported_encoding = HeaderMap::new();
        unsupported_encoding.insert(CONTENT_ENCODING, HeaderValue::from_static("br"));
        let unsupported_error =
            validate_representation_headers(&unsupported_encoding, GitRequestKind::UploadPackPost)
                .unwrap_err();
        assert_eq!(
            unsupported_error.reason_code(),
            ReasonCode::GatewayHeaderDenied
        );

        let mut comma_encoding = HeaderMap::new();
        comma_encoding.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip, br"));
        let comma_error =
            validate_representation_headers(&comma_encoding, GitRequestKind::UploadPackPost)
                .unwrap_err();
        assert_eq!(comma_error.reason_code(), ReasonCode::GatewayHeaderDenied);

        let mut empty_encoding = HeaderMap::new();
        empty_encoding.insert(CONTENT_ENCODING, HeaderValue::from_static(""));
        let empty_error =
            validate_representation_headers(&empty_encoding, GitRequestKind::UploadPackPost)
                .unwrap_err();
        assert_eq!(empty_error.reason_code(), ReasonCode::GatewayHeaderDenied);

        let mut receive_pack_headers = HeaderMap::new();
        receive_pack_headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        let receive_pack_error =
            validate_representation_headers(&receive_pack_headers, GitRequestKind::ReceivePackPost)
                .unwrap_err();
        assert_eq!(
            receive_pack_error.reason_code(),
            ReasonCode::GatewayHeaderDenied
        );

        let mut discovery_headers = HeaderMap::new();
        discovery_headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        let discovery_error = validate_representation_headers(
            &discovery_headers,
            GitRequestKind::UploadPackDiscovery,
        )
        .unwrap_err();
        assert_eq!(
            discovery_error.reason_code(),
            ReasonCode::GatewayHeaderDenied
        );

        let mut trailer_headers = HeaderMap::new();
        trailer_headers.insert(TRAILER, HeaderValue::from_static("Content-MD5"));
        let trailer_error =
            validate_representation_headers(&trailer_headers, GitRequestKind::UploadPackPost)
                .unwrap_err();
        assert_eq!(trailer_error.reason_code(), ReasonCode::GatewayHeaderDenied);
    }
}
