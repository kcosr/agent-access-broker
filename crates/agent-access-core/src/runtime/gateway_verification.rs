//! Host authority and bounded transport for linked gateway verification probes.
use super::*;
use agent_access_provider::{GatewayHookPhase, GatewayProbeStatus, GatewayVerificationProbe};

fn contract_failure() -> ProviderError {
    ProviderError::error(
        ReasonCode::BrokerProviderContractFailed,
        "gateway module violated its host contract",
    )
}

impl BrokerRuntime {
    fn gateway_verification_probe(
        &self,
        service: &str,
        input: Option<&str>,
    ) -> Result<Box<dyn GatewayVerificationProbe>, ProviderError> {
        let descriptor = self.services.get(service).ok_or_else(|| {
            ProviderError::deny(ReasonCode::ServiceActionDenied, "service is not supported")
        })?;
        if !descriptor.credentials.verification_supported {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "service has no eligible credential verification consumer",
            ));
        }
        let registration = self
            .gateway_registration(service)
            .ok_or_else(contract_failure)?;
        let protocol = self
            .gateway_protocol(service)
            .ok_or_else(contract_failure)?;
        let probe = protocol
            .verification(input)
            .map_err(|error| self.gateway_probe_failure(service, error))?
            .ok_or_else(contract_failure)?;
        let request = probe.request();
        let action = descriptor
            .action(&request.action)
            .ok_or_else(contract_failure)?;
        if !action.read_only
            || request.max_response_bytes == 0
            || request.max_response_bytes as u128
                > u128::from(self.config.limits.max_upstream_response_bytes)
            || request.normalized_input.len() > 8192
            || !valid_probe_headers(&request.headers)
            || request.audit.as_ref().is_some_and(|audit| {
                serde_json::to_vec(audit).map_or(true, |bytes| bytes.len() > 16 * 1024)
            })
            || request.audit_target.as_ref().is_some_and(|path| {
                !path.starts_with('/')
                    || path.len() > 8192
                    || path.contains(['?', '#'])
                    || path.chars().any(char::is_control)
            })
        {
            return Err(contract_failure());
        }
        match &action.resource_scope {
            None if !request.scopes.is_empty() => return Err(contract_failure()),
            Some(scope)
                if request.scopes.len() != 1
                    || request.scopes.get(scope).is_none_or(Vec::is_empty) =>
            {
                return Err(contract_failure());
            }
            _ => {}
        }
        let _ = registration;
        self.gateway_config(service)
            .ok_or_else(contract_failure)?
            .upstream_url(&request.relative_target)?;
        Ok(probe)
    }

    fn gateway_probe_failure(&self, service: &str, error: ProviderError) -> ProviderError {
        if self
            .gateway_registration(service)
            .is_some_and(|registration| {
                registration
                    .check_failure(GatewayHookPhase::Verification, &error)
                    .is_ok()
            })
        {
            error
        } else {
            contract_failure()
        }
    }

    pub fn preflight_execution_credential_verification(
        &self,
        service: &str,
        identity: &IdentityContext,
        input: CredentialVerificationInput,
    ) -> Result<CredentialVerificationInput, ProviderError> {
        if self.providers.contains_key(service) {
            if !self
                .services
                .get(service)
                .is_some_and(|descriptor| descriptor.credentials.verification_supported)
            {
                return Err(ProviderError::deny(
                    ReasonCode::ServiceActionDenied,
                    "service has no eligible credential verification consumer",
                ));
            }
            if !input.is_empty() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "credential verification input is not supported for service",
                ));
            }
            return Ok(input);
        }
        let probe = self.gateway_verification_probe(service, input.repository.as_deref())?;
        let request = probe.request();
        let policy_snapshot = self.policy_snapshot();
        let permitted = self
            .policy_candidates_for_action_across_contexts(
                &policy_snapshot,
                identity,
                service,
                &request.action,
            )
            .into_iter()
            .any(|candidate| {
                candidate.credential_mode == "per_user"
                    && candidate_authorizes_scopes(&candidate, &request.scopes)
            });
        if !permitted {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                format!(
                    "gateway credential verification requires a per_user {} policy",
                    request.action
                ),
            ));
        }
        Ok(CredentialVerificationInput {
            repository: Some(request.normalized_input.clone()),
        })
    }

    pub(super) async fn verify_gateway_execution_credential(
        &self,
        service: &str,
        gateway: &GatewayConfig,
        credential: &ExecutionCredential,
        _identity: &IdentityContext,
        input: CredentialVerificationInput,
        correlation: CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        let probe = self.gateway_verification_probe(service, input.repository.as_deref())?;
        let request = probe.request();
        self.check_gateway_presentable(credential)?;
        let url = gateway.upstream_url(&request.relative_target)?;
        let (client, egress) = self.gateway_http_client(service, gateway).map_err(|_| {
            ProviderError::error(
                ReasonCode::GatewayUpstreamDenied,
                "gateway upstream client is unavailable",
            )
        })?;
        let mut builder = client
            .request(request.method.clone(), url.clone())
            .headers(request.headers.clone());
        if gateway.correlation_headers {
            builder = builder
                .header(REQUEST_ID_HEADER, correlation.agent_request_id.clone())
                .header(
                    BROKER_REQUEST_ID_HEADER,
                    correlation.broker_request_id.clone(),
                );
        }
        builder = agent_access_provider::host::authorize_host_request(
            builder,
            &gateway_upstream_authorization(&gateway.upstream_token_auth, credential)?,
        );
        let mut audit = json!({"gateway": {
            "kind": gateway.kind, "operation": "credential.verify", "method": request.method.as_str(),
            "upstreamOrigin": url.origin().ascii_serialization(),
            "upstreamPath": request.audit_target.as_deref().unwrap_or_else(|| url.path()),
            "egressProxy": egress, "responseBytes": 0,
        }});
        if let Some(facts) = &request.audit {
            let key = self
                .gateway_registration(service)
                .ok_or_else(contract_failure)?
                .audit_key();
            if key == "gateway" {
                if let Some(facts) = facts.as_object() {
                    for (key, value) in facts {
                        if audit["gateway"].get(key).is_none()
                            && !matches!(
                                key.as_str(),
                                "phase"
                                    | "message"
                                    | "credentialMethod"
                                    | "durationMs"
                                    | "upstreamStatus"
                                    | "transferOutcome"
                                    | "requestBytes"
                            )
                        {
                            audit["gateway"][key] = value.clone();
                        }
                    }
                }
            } else {
                audit[key] = facts.clone();
            }
        }
        let started = Instant::now();
        let budget = Duration::from_millis(
            gateway
                .streaming_idle_timeout_ms
                .unwrap_or(self.config.limits.streaming_idle_timeout_ms),
        );
        let mut response = match timeout(budget, builder.send()).await {
            Ok(Ok(response)) => response,
            outcome => {
                let code = match outcome {
                    Ok(Err(ref error)) if error.is_connect() => {
                        ReasonCode::UpstreamConnectionFailed
                    }
                    Ok(Err(ref error)) if !error.is_timeout() => ReasonCode::UpstreamFailed,
                    _ => ReasonCode::UpstreamTimeout,
                };
                return Err(ProviderError::error(
                    code,
                    "gateway upstream credential verification failed",
                )
                .with_upstream(None, Some(elapsed_millis(started)))
                .with_audit(audit));
            }
        };
        let status = response.status().as_u16();
        audit["gateway"]["upstreamStatus"] = json!(status);
        if status == 429 {
            return Err(upstream_rate_limited(
                service,
                UpstreamRetryAfter::from_headers(response.headers()),
            )
            .with_upstream(Some(status), Some(elapsed_millis(started)))
            .with_audit(audit));
        }
        let headers = response.headers().clone();
        let mut prefix = Vec::new();
        let validated = timeout(budget, async {
            let mut eof = false;
            loop {
                let outcome = probe
                    .validate_response(status, &headers, &prefix, eof)
                    .map_err(|error| self.gateway_probe_failure(service, error))?;
                match outcome {
                    GatewayProbeStatus::Valid => return Ok(()),
                    GatewayProbeStatus::NeedMore
                        if !eof && prefix.len() < request.max_response_bytes => {}
                    _ => {
                        return Err(ProviderError::error(
                            ReasonCode::UpstreamProtocolFailed,
                            "gateway upstream did not satisfy credential verification",
                        ));
                    }
                }
                let chunk = response.chunk().await.map_err(|_| {
                    ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "gateway upstream verification response could not be read",
                    )
                })?;
                match chunk {
                    Some(bytes) => {
                        let remaining = request.max_response_bytes - prefix.len();
                        prefix.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
                    }
                    None => eof = true,
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            Err(ProviderError::error(
                ReasonCode::UpstreamTimeout,
                "gateway upstream verification response timed out",
            ))
        });
        validated.map_err(|error| {
            error
                .with_upstream(Some(status), Some(elapsed_millis(started)))
                .with_audit(audit.clone())
        })?;
        Ok(Some(ProviderCredentialVerification::new(
            status,
            elapsed_millis(started),
            audit,
        )))
    }
}

fn reserved_probe_header(name: &str) -> bool {
    name.starts_with("x-aw-")
        || name.starts_with("x-agent-access-")
        || name.starts_with("proxy-")
        || name.starts_with("x-forwarded-")
        || matches!(
            name,
            "authorization"
                | "host"
                | "cookie"
                | "set-cookie"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "content-length"
                | "trailer"
                | "te"
                | "upgrade"
                | "forwarded"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
                | "x-real-ip"
                | "true-client-ip"
                | "cf-connecting-ip"
                | "x-client-ip"
                | "via"
                | "x-request-id"
                | "x-broker-request-id"
        )
}

fn valid_probe_headers(headers: &reqwest::header::HeaderMap) -> bool {
    headers.len() <= 128
        && headers
            .iter()
            .try_fold(0usize, |bytes, (name, value)| {
                bytes
                    .checked_add(name.as_str().len())?
                    .checked_add(value.as_bytes().len())
            })
            .is_some_and(|bytes| bytes <= 64 * 1024)
        && !headers
            .keys()
            .any(|name| reserved_probe_header(name.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn probe_headers_bound_total_bytes_and_count_before_transport() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-probe",
            HeaderValue::from_str(&"a".repeat(64 * 1024 - 7)).unwrap(),
        );
        assert!(valid_probe_headers(&headers));
        headers.append("x-probe", HeaderValue::from_static("b"));
        assert!(!valid_probe_headers(&headers));
        headers.clear();
        for _ in 0..128 {
            headers.append("x-probe", HeaderValue::from_static("a"));
        }
        assert!(valid_probe_headers(&headers));
        headers.append("x-probe", HeaderValue::from_static("a"));
        assert!(!valid_probe_headers(&headers));
        headers.clear();
        headers.insert("authorization", HeaderValue::from_static("redacted"));
        assert!(!valid_probe_headers(&headers));
    }
}
