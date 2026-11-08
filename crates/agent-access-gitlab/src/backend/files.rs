//! Repository-file headers identify the exact blob that a raw response serves.
use super::*;
use reqwest::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap};

pub(crate) const GITLAB_FILE_METADATA_MAX_BYTES: usize = 16 * 1024;

const FILE_HEADERS: &[&str] = &[
    "x-gitlab-file-name",
    "x-gitlab-file-path",
    "x-gitlab-size",
    "x-gitlab-commit-id",
    "x-gitlab-content-sha256",
    "x-gitlab-ref",
    "x-gitlab-blob-id",
    "x-gitlab-last-commit-id",
    "x-gitlab-execute-filemode",
    "content-type",
    "content-length",
    "content-encoding",
];

impl HttpGitlabBackend {
    pub(super) async fn head_repository_file(
        &self,
        project_id: u64,
        request: GitlabFileRequest,
        credential: &GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabFileMetadata>, GitlabBackendError> {
        let started = Instant::now();
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/repository/files/{}",
            encoded_path_segment(&request.path)
        ))?;
        url.query_pairs_mut().append_pair("ref", &request.ref_name);
        let response = send_gitlab_request(
            &self.client,
            credential,
            self.client
                .request(Method::HEAD, url)
                .header("Accept", "application/json"),
            "file.view",
            None,
            self.limits.max_upstream_response_bytes,
        )
        .await?;
        require_file_status(&response)?;
        let metadata = file_metadata_from_headers(response.headers(), &request.path)?;
        // A HEAD's Content-Length describes a representation, not a body.
        // Neither content_length() nor a body reader belongs on this path.
        Ok(GitlabBackendResponse {
            value: metadata,
            status: response.status().as_u16(),
            duration_ms: elapsed_ms(started),
        })
    }

    pub(super) async fn get_repository_file(
        &self,
        operation: &'static str,
        project_id: u64,
        request: GitlabFileRequest,
        byte_cap: u64,
        credential: &GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabRepositoryFile>, GitlabBackendError> {
        let started = Instant::now();
        let mut url = self.endpoint(&format!(
            "projects/{project_id}/repository/files/{}/raw",
            encoded_path_segment(&request.path)
        ))?;
        url.query_pairs_mut().append_pair("ref", &request.ref_name);
        let response = send_gitlab_request(
            &self.client,
            credential,
            self.client
                .request(Method::GET, url)
                .header("Accept", "application/octet-stream")
                .header("Accept-Encoding", "identity"),
            operation,
            None,
            byte_cap,
        )
        .await?;
        require_file_status(&response)?;
        let status = response.status().as_u16();
        let metadata = file_metadata_from_headers(response.headers(), &request.path)?;
        if let Some(encoding) = file_header(response.headers(), CONTENT_ENCODING.as_str())?
            && !encoding.eq_ignore_ascii_case("identity")
        {
            return Err(file_protocol("GitLab raw file response is content-encoded"));
        }
        if let Some(length) = file_header(response.headers(), CONTENT_LENGTH.as_str())? {
            let length = file_size(length)?;
            if length != metadata.size {
                return Err(file_protocol(
                    "GitLab raw file Content-Length did not match metadata",
                ));
            }
        }
        let content_type = file_header(response.headers(), CONTENT_TYPE.as_str())?
            .unwrap_or("application/octet-stream")
            .to_string();
        let stream = if metadata.size > byte_cap {
            // Do not drain a response merely to reuse the connection. Some
            // network read-ahead may have happened, but no body is consumed here.
            None
        } else {
            Some(gitlab_response_stream(
                response,
                byte_cap,
                Duration::from_millis(self.limits.streaming_idle_timeout_ms),
                Some(metadata.size),
                content_type.clone(),
            ))
        };
        Ok(GitlabBackendResponse {
            value: GitlabRepositoryFile {
                metadata,
                content_type,
                stream,
            },
            status,
            duration_ms: elapsed_ms(started),
        })
    }
}

fn require_file_status(response: &reqwest::Response) -> Result<(), GitlabBackendError> {
    if response.status() != reqwest::StatusCode::OK {
        return Err(file_protocol("GitLab file response status was not 200"));
    }
    Ok(())
}

fn file_metadata_from_headers(
    headers: &HeaderMap,
    requested_path: &str,
) -> Result<GitlabFileMetadata, GitlabBackendError> {
    let mut header_bytes = 0_usize;
    for name in FILE_HEADERS {
        for value in headers.get_all(*name) {
            header_bytes = header_bytes.saturating_add(value.as_bytes().len());
            if header_bytes > GITLAB_FILE_METADATA_MAX_BYTES {
                return Err(file_protocol(
                    "GitLab file metadata exceeded the header limit",
                ));
            }
        }
    }
    let file_path = required_file_header(headers, "x-gitlab-file-path")?;
    if file_path != requested_path {
        return Err(file_protocol(
            "GitLab file metadata did not match the requested path",
        ));
    }
    let file_name = required_file_header(headers, "x-gitlab-file-name")?;
    if Some(file_name) != file_path.rsplit('/').next() {
        return Err(file_protocol("GitLab file name did not match its path"));
    }
    let mut metadata = GitlabFileMetadata::new(
        file_name.to_string(),
        file_path.to_string(),
        file_size(required_file_header(headers, "x-gitlab-size")?)?,
        file_object_id(required_file_header(headers, "x-gitlab-commit-id")?)?.to_string(),
    );
    metadata.content_sha256 = optional_metadata_header(headers, "x-gitlab-content-sha256")?
        .map(|hash| {
            if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(file_protocol("GitLab file content SHA-256 is invalid"));
            }
            Ok(hash.to_string())
        })
        .transpose()?;
    metadata.ref_name = optional_metadata_header(headers, "x-gitlab-ref")?.map(str::to_string);
    metadata.blob_id = optional_metadata_header(headers, "x-gitlab-blob-id")?
        .map(|value| file_object_id(value).map(str::to_string))
        .transpose()?;
    metadata.last_commit_id = optional_metadata_header(headers, "x-gitlab-last-commit-id")?
        .map(|value| file_object_id(value).map(str::to_string))
        .transpose()?;
    metadata.execute_filemode = optional_metadata_header(headers, "x-gitlab-execute-filemode")?
        .map(|value| match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(file_protocol("GitLab file executable flag is invalid")),
        })
        .transpose()?;
    Ok(metadata)
}

fn file_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, GitlabBackendError> {
    let value = file_header_value(headers, name)?;
    if value.is_some_and(str::is_empty) {
        return Err(file_protocol(
            "GitLab file metadata contains an invalid value",
        ));
    }
    Ok(value)
}

fn optional_metadata_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, GitlabBackendError> {
    // GitLab stringifies nullable metadata values into empty header values.
    // Duplicates, invalid UTF-8 and control characters still fail first.
    Ok(file_header_value(headers, name)?.filter(|value| !value.is_empty()))
}

fn file_header_value<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, GitlabBackendError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(file_protocol(
            "GitLab file metadata contains a duplicate header",
        ));
    }
    let value = std::str::from_utf8(value.as_bytes())
        .map_err(|_| file_protocol("GitLab file metadata is not UTF-8"))?;
    if value.chars().any(char::is_control) {
        return Err(file_protocol(
            "GitLab file metadata contains an invalid value",
        ));
    }
    Ok(Some(value))
}

fn required_file_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<&'a str, GitlabBackendError> {
    file_header(headers, name)?
        .ok_or_else(|| file_protocol("GitLab file metadata is missing a required header"))
}

fn file_size(value: &str) -> Result<u64, GitlabBackendError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(file_protocol("GitLab file size is invalid"));
    }
    value
        .parse()
        .map_err(|_| file_protocol("GitLab file size is invalid"))
}

fn file_object_id(value: &str) -> Result<&str, GitlabBackendError> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(file_protocol("GitLab file object ID is invalid"));
    }
    Ok(value)
}

fn file_protocol(message: &str) -> GitlabBackendError {
    GitlabBackendError::Protocol(message.to_string())
}

#[cfg(test)]
mod tests;
