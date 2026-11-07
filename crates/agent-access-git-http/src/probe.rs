use agent_access_provider::{
    GatewayProbeRequest, GatewayProbeStatus, GatewayVerificationProbe, ResourceScopes,
};
use agent_access_provider::{ProviderError, ReasonCode};
use http::{HeaderMap, HeaderValue};

#[derive(Debug)]
pub(crate) struct GitProbe {
    request: GatewayProbeRequest,
}

impl GitProbe {
    pub(crate) fn new(input: Option<&str>) -> Result<Self, ProviderError> {
        let repository = normalize_repository(input)?;
        let mut url = url::Url::parse("https://gateway.invalid/").expect("literal base URL");
        {
            let mut segments = url.path_segments_mut().expect("literal hierarchical base");
            segments.clear();
            let mut repository_segments =
                repository.split('/').map(str::to_owned).collect::<Vec<_>>();
            if let Some(last) = repository_segments.last_mut()
                && !last.ends_with(".git")
            {
                last.push_str(".git");
            }
            segments.extend(repository_segments.iter().map(String::as_str));
            segments.push("info");
            segments.push("refs");
        }
        url.set_query(Some("service=git-upload-pack"));
        let headers = HeaderMap::from_iter([
            (http::header::ACCEPT, HeaderValue::from_static("*/*")),
            (
                http::header::USER_AGENT,
                HeaderValue::from_static("agent-access-broker/git-credential-verify"),
            ),
        ]);
        Ok(Self {
            request: GatewayProbeRequest::new(
                "repo.fetch",
                ResourceScopes::from([("repository".into(), vec![repository.clone()])]),
                repository,
                url[url::Position::BeforePath..].to_owned(),
                GIT_UPLOAD_PACK_ADVERTISEMENT_PREFIX_MAX_BYTES,
            )
            .with_headers(headers),
        })
    }
}

impl GatewayVerificationProbe for GitProbe {
    fn request(&self) -> &GatewayProbeRequest {
        &self.request
    }

    fn validate_response(
        &self,
        status: u16,
        headers: &HeaderMap,
        prefix: &[u8],
        eof: bool,
    ) -> Result<GatewayProbeStatus, ProviderError> {
        if !(200..300).contains(&status) {
            return Err(git_verify_status_error(status));
        }
        let invalid = || {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "git upstream did not return upload-pack discovery",
            )
        };
        if !git_upload_pack_discovery_content_type_is_valid(headers) {
            return Err(invalid());
        }
        match git_upload_pack_advertisement_prefix(prefix) {
            GitAdvertisementPrefix::Valid => Ok(GatewayProbeStatus::Valid),
            GitAdvertisementPrefix::NeedMore
                if !eof && prefix.len() < GIT_UPLOAD_PACK_ADVERTISEMENT_PREFIX_MAX_BYTES =>
            {
                Ok(GatewayProbeStatus::NeedMore)
            }
            _ => Err(invalid()),
        }
    }
}

pub(crate) fn normalize_repository(repository: Option<&str>) -> Result<String, ProviderError> {
    let repository = repository
        .map(str::trim)
        .filter(|repository| !repository.is_empty())
        .ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "git credential verification requires repository",
            )
        })?;
    if !agent_access_provider::is_repository_selector_path(repository) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "git credential verification repository is invalid",
        ));
    }
    let mut segments = repository
        .split('/')
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if segments[..segments.len().saturating_sub(1)]
        .iter()
        .any(|segment| segment.ends_with(".git"))
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "git credential verification repository is invalid",
        ));
    }
    if let Some(last) = segments.last_mut()
        && let Some(stripped) = last.strip_suffix(".git")
    {
        *last = stripped.to_string();
    }
    let repository = segments.join("/");
    if !agent_access_provider::is_repository_selector_path(&repository) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "git credential verification repository is invalid",
        ));
    }
    Ok(repository)
}

fn git_verify_status_error(status: u16) -> ProviderError {
    match status {
        401 => ProviderError::error(
            ReasonCode::UpstreamUnauthorized,
            "git upstream rejected the selected credential",
        ),
        403 => ProviderError::error(
            ReasonCode::UpstreamForbidden,
            "git upstream forbids the selected credential",
        ),
        404 => ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "git repository was not found or unavailable",
        ),
        _ => ProviderError::error(
            ReasonCode::UpstreamFailed,
            "git upstream credential verification failed",
        ),
    }
}

const GIT_UPLOAD_PACK_ADVERTISEMENT_PREFIX_MAX_BYTES: usize = 1024;

fn git_upload_pack_discovery_content_type_is_valid(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::CONTENT_TYPE)
        .iter()
        .any(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.split(';').next())
                .map(str::trim)
                .is_some_and(|value| {
                    value.eq_ignore_ascii_case("application/x-git-upload-pack-advertisement")
                })
        })
}

enum GitAdvertisementPrefix {
    NeedMore,
    Valid,
    Invalid,
}

fn git_upload_pack_advertisement_prefix(prefix: &[u8]) -> GitAdvertisementPrefix {
    if prefix.len() < 4 {
        return GitAdvertisementPrefix::NeedMore;
    }
    let Ok(length_hex) = std::str::from_utf8(&prefix[..4]) else {
        return GitAdvertisementPrefix::Invalid;
    };
    let Ok(length) = usize::from_str_radix(length_hex, 16) else {
        return GitAdvertisementPrefix::Invalid;
    };
    if length < 4 {
        return GitAdvertisementPrefix::Invalid;
    }
    if length > GIT_UPLOAD_PACK_ADVERTISEMENT_PREFIX_MAX_BYTES {
        return GitAdvertisementPrefix::Invalid;
    }
    if prefix.len() < length {
        return GitAdvertisementPrefix::NeedMore;
    }
    let payload = &prefix[4..length];
    if payload == b"# service=git-upload-pack\n" {
        GitAdvertisementPrefix::Valid
    } else {
        GitAdvertisementPrefix::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_repository_input_is_normalized_without_accepting_urls_or_ambiguous_suffixes() {
        assert_eq!(
            normalize_repository(Some(" team/project.git ")).unwrap(),
            "team/project"
        );
        assert_eq!(
            normalize_repository(Some("team/project.git.git")).unwrap(),
            "team/project.git"
        );
        for repository in [
            None,
            Some(""),
            Some("https://git.example/team/project"),
            Some("team.git/project"),
            Some("team/../project"),
            Some("team/project%2fother"),
        ] {
            assert_eq!(
                normalize_repository(repository).unwrap_err().reason_code(),
                ReasonCode::InputInvalid,
                "{repository:?}"
            );
        }
    }

    #[test]
    fn successful_status_or_content_type_alone_does_not_verify_git() {
        let valid = b"001e# service=git-upload-pack\n";
        for length in 0..valid.len() {
            assert!(matches!(
                git_upload_pack_advertisement_prefix(&valid[..length]),
                GitAdvertisementPrefix::NeedMore
            ));
        }
        assert!(matches!(
            git_upload_pack_advertisement_prefix(valid),
            GitAdvertisementPrefix::Valid
        ));
        for invalid in [
            b"0000".as_slice(),
            b"zzzz",
            b"0004",
            b"<html>ok</html>",
            b"ffff",
        ] {
            assert!(
                matches!(
                    git_upload_pack_advertisement_prefix(invalid),
                    GitAdvertisementPrefix::Invalid
                ),
                "{invalid:?}"
            );
        }
        let headers = http::HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static(
                "application/x-git-upload-pack-advertisement; charset=utf-8",
            ),
        )]);
        assert!(git_upload_pack_discovery_content_type_is_valid(&headers));
        assert!(!git_upload_pack_discovery_content_type_is_valid(
            &http::HeaderMap::new()
        ));
    }
}
