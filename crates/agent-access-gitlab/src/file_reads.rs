//! Repository file metadata and complete, explicitly budgeted text reads.
use super::*;
use futures_util::StreamExt;

impl GitlabProvider {
    pub(super) async fn invoke_file_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs =
            parse_file_view_inputs(request.inputs(), self.config.content.max_inline_text_bytes)?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let file_request = GitlabFileRequest {
            path: inputs.locator.path.clone(),
            ref_name: inputs.locator.ref_name.clone(),
        };
        let (metadata, status, duration_ms, content_status, content) = if inputs.include_content {
            let response = self
                .backend
                .raw_file(
                    "file.view",
                    project.id,
                    file_request,
                    inputs.content_budget_bytes,
                    credential,
                )
                .await
                .map_err(gitlab_backend_error)?;
            let file = response.value;
            let (content_status, content) = if file.metadata.size > inputs.content_budget_bytes {
                ("too_large", None)
            } else {
                let stream = file.stream.ok_or_else(missing_file_stream)?;
                let bytes =
                    read_inline_bytes(stream, file.metadata.size, inputs.content_budget_bytes)
                        .await?;
                match String::from_utf8(bytes) {
                    Ok(text) if !text.contains('\0') => ("included", Some(text)),
                    _ => ("unsupported_text", None),
                }
            };
            (
                file.metadata,
                response.status,
                response.duration_ms,
                content_status,
                content,
            )
        } else {
            let response = self
                .backend
                .file_metadata(project.id, file_request, credential)
                .await
                .map_err(gitlab_backend_error)?;
            (
                response.value,
                response.status,
                response.duration_ms,
                "not_requested",
                None,
            )
        };
        validate_read_path(&inputs.locator.path, &metadata)?;
        let mut file = file_metadata_result(&metadata, &inputs.locator.ref_name);
        file["contentStatus"] = json!(content_status);
        if let Some(content) = content {
            file["content"] = json!(content);
        }
        if content_status == "too_large" {
            file["contentBudgetBytes"] = json!(inputs.content_budget_bytes);
        }
        // This is an independent result bound, not an MCP delivery guarantee:
        // transport framing, structured/text duplication and rendering still count.
        let result = json!({ "file": file });
        if serde_json::to_vec(&result)
            .map_err(|_| {
                ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "GitLab file result could not be encoded",
                )
            })?
            .len() as u64
            > self.limits.max_upstream_response_bytes
        {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab file result exceeded the JSON response limit",
            ));
        }
        let mut result = gitlab_result(
            "file.view",
            &project,
            Some(
                json!({"file": format!("{}:{}:{}", project.path_with_namespace, inputs.locator.ref_name, metadata.file_path)}),
            ),
            status,
            duration_ms,
            result,
            self.backend.egress_proxy_audit(credential),
        );
        let mut audit_fields = vec![("contentStatus", json!(content_status))];
        if inputs.include_content {
            audit_fields.push(("contentBudgetBytes", json!(inputs.content_budget_bytes)));
        }
        add_gitlab_audit_fields(&mut result, audit_fields);
        Ok(result)
    }

    pub(super) async fn invoke_file_raw_download(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_file_locator_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let byte_cap = self
            .config
            .content
            .max_raw_download_bytes
            .min(self.limits.max_download_bytes);
        let response = self
            .backend
            .raw_file(
                "file.raw.download",
                project.id,
                GitlabFileRequest {
                    path: inputs.path.clone(),
                    ref_name: inputs.ref_name.clone(),
                },
                byte_cap,
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        let file = response.value;
        let metadata = file.metadata;
        validate_read_path(&inputs.path, &metadata)?;
        validate_gitlab_raw_download_size(metadata.size, byte_cap)?;
        let stream = file.stream.ok_or_else(missing_file_stream)?;
        // GitLab's content_sha256 can hash transcoded JSON content. It is not
        // an expected checksum for this raw stream. Clients hash delivered bytes.
        let result = json!({
            "project": project.path_with_namespace,
            "projectId": project.id,
            "path": metadata.file_path,
            "ref": inputs.ref_name,
            "resolvedRef": metadata.commit_id,
            "contentType": file.content_type,
            "size": metadata.size,
        });
        let audit = json!({"gitlab": {
            "operation": "file.raw.download",
            "project": project.path_with_namespace,
            "namespace": project.path_with_namespace.split('/').next().unwrap_or(""),
            "projectId": project.id,
            "path": result["path"], "ref": result["ref"], "resolvedRef": result["resolvedRef"],
            "contentType": result["contentType"], "size": metadata.size,
            "egressProxy": self.backend.egress_proxy_audit(credential),
        }});
        Ok(ProviderResult::new(result)
            .with_stream(stream.with_expected_size(metadata.size, "GitLab raw file response size did not match metadata"))
            .with_audit(audit)
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({"file": format!("{}:{}:{}", project.path_with_namespace, inputs.ref_name, inputs.path)})))
    }
}

fn missing_file_stream() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "GitLab file response did not include its body",
    )
}

fn validate_read_path(expected: &str, metadata: &GitlabFileMetadata) -> Result<(), ProviderError> {
    if metadata.file_path != expected {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab file path did not match the request",
        ));
    }
    Ok(())
}

fn file_metadata_result(metadata: &GitlabFileMetadata, requested_ref: &str) -> Value {
    json!({
        "fileName": metadata.file_name, "filePath": metadata.file_path,
        "size": metadata.size, "contentSha256": metadata.content_sha256,
        "ref": requested_ref, "blobId": metadata.blob_id,
        "commitId": metadata.commit_id, "lastCommitId": metadata.last_commit_id,
        "executeFilemode": metadata.execute_filemode,
    })
}

async fn read_inline_bytes(
    body: ProviderResultStream,
    expected_size: u64,
    byte_cap: u64,
) -> Result<Vec<u8>, ProviderError> {
    let invalid_size = || {
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab file body size did not match its bounded metadata",
        )
    };
    let bytes = match body.source {
        ProviderResultStreamSource::Memory(bytes) => bytes,
        ProviderResultStreamSource::Stream(source) => {
            let mut stream = source
                .lock()
                .map_err(|_| missing_file_stream())?
                .take()
                .ok_or_else(missing_file_stream)?;
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| {
                    let reason = match error.reason_code.standard() {
                        Some(ReasonCode::UpstreamTimeout) => ReasonCode::UpstreamTimeout,
                        Some(ReasonCode::UpstreamConnectionFailed) => {
                            ReasonCode::UpstreamConnectionFailed
                        }
                        _ => ReasonCode::UpstreamProtocolFailed,
                    };
                    ProviderError::error(reason, error.message)
                })?;
                let next_size = (bytes.len() as u64)
                    .checked_add(chunk.len() as u64)
                    .ok_or_else(invalid_size)?;
                if next_size > byte_cap || next_size > expected_size {
                    return Err(invalid_size());
                }
                bytes.extend_from_slice(&chunk);
            }
            bytes
        }
    };
    if bytes.len() as u64 != expected_size || bytes.len() as u64 > byte_cap {
        return Err(invalid_size());
    }
    Ok(bytes)
}
