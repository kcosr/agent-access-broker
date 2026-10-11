//! Development-only typed resource adapter for the independent OAuth test server.
use crate::*;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Instant;

/// Collections served by the development OAuth test provider.
pub static OAUTH_COLLECTION_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor {
    action_inputs: None,
    attributes: &[],
    id: ResourceType::from_static("oauth_collection"),
    label: "OAuth test collection",
    plural_label: "OAuth test collections",
    example: "alpha",
    canonical: crate::resource_policy::is_oauth_collection,
    namespace: None,
};

/// The OAuth test-records service. Its per-user credential is the caller's
/// delegated OAuth connection.
pub(crate) fn oauth_records_descriptor() -> ServiceDescriptor {
    let collection = || json!({"type":"string","pattern":"^[a-z0-9_-]{1,64}$"});
    let schema = |required: Value, properties: Value| json!({"type":"object","required":required,"properties":properties,"additionalProperties":false});
    ServiceDescriptor {
        service: "oauth_stub".into(),
        display_name: "OAuth Test Records".into(),
        surface: ServiceSurface::Invoke,
        resource_scopes: BTreeMap::from([(
            "collection".into(),
            ResourceScopeCapabilities {
                resource_type: crate::oauth_records::OAUTH_COLLECTION_RESOURCE.id.clone(),
                selectors: vec!["exact".into(), "all".into()],
            },
        )]),
        actions: vec![
            ActionDescriptor::new(
                "record.list",
                "List records in an authorized test collection",
                schema(json!(["collection"]), json!({"collection": collection()})),
            )
            .read_only()
            .scope("collection")
            .credential_modes(["per_user"]),
            ActionDescriptor::new(
                "record.view",
                "Read one record in an authorized test collection",
                schema(
                    json!(["collection", "id"]),
                    json!({
                        "collection": collection(),
                        "id": {"type":"string","pattern":"^[a-zA-Z0-9_-]{1,128}$"}
                    }),
                ),
            )
            .read_only()
            .scope("collection")
            .credential_modes(["per_user"]),
            ActionDescriptor::new(
                "account.view",
                "Read the connected test account identity",
                schema(json!([]), json!({})),
            )
            .read_only()
            .credential_modes(["per_user"]),
        ],
        credentials: CredentialDescriptor::default()
            .delegated("Lets agents read the test records your account can reach."),
        presentation_body_limit: None,
    }
}

/// The records API at the stub's base URL. The runtime lends each invocation
/// the caller's delegated OAuth access; the provider only presents it.
pub(crate) struct OAuthRecordsProvider {
    client: UpstreamClient,
    max_bytes: u64,
}

impl OAuthRecordsProvider {
    pub(crate) fn new(
        registration: &OAuthRegistrationConfig,
        network: UpstreamNetwork<'_>,
    ) -> Result<Self, HostError> {
        let base = url::Url::parse(&format!("{}/", registration.base_url.trim_end_matches('/')))
            .map_err(|_| HostError::invalid("oauth.registrations base_url is invalid"))?;
        // Like the registration's authorization server, a loopback records
        // API is reached directly.
        let direct = EgressProxyRuntimeConfig::direct();
        let network = if crate::oauth::is_loopback(&base) {
            UpstreamNetwork {
                egress: &direct,
                ..network
            }
        } else {
            network
        };
        let client = UpstreamClient::build(
            UpstreamClientSpec {
                label: "credentials.per_user.oauth_stub",
                provider: "oauth_stub",
                base: &base,
                egress_proxy: None,
                allowed_upstream_hosts: &[format!("{base}**")],
                profile: ClientProfile::Request,
                status_reasons: &[],
            },
            network,
        )?;
        Ok(Self {
            client,
            max_bytes: network.limits.max_upstream_response_bytes.min(1024 * 1024),
        })
    }

    async fn send(
        &self,
        url: &url::Url,
        access: &DelegatedAccess,
        attempt: u32,
    ) -> Result<reqwest::Response, ProviderError> {
        let request = self
            .client
            .request(reqwest::Method::GET, url.clone())
            .bearer_auth(&access.token)
            .header("X-Stub-Target", &access.target)
            .header("X-Stub-Audience", &access.audience);
        self.client
            .send(
                request,
                UpstreamCall {
                    operation: "records.read",
                    attempt,
                },
            )
            .await
            .map_err(|error| {
                ProviderError::error(error.reason_code(), "OAuth records upstream unavailable")
            })
    }

    async fn read_body(&self, mut response: reqwest::Response) -> Result<Value, ProviderError> {
        if !response.status().is_success() {
            complete_upstream_trace(&mut response, Some(ReasonCode::UpstreamFailed));
            return Err(ProviderError::error(
                ReasonCode::UpstreamFailed,
                "OAuth records request failed",
            ));
        }
        let too_large = || {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "OAuth records response exceeds limit",
            )
        };
        if response
            .content_length()
            .is_some_and(|n| n > self.max_bytes)
        {
            complete_upstream_trace(&mut response, Some(ReasonCode::UpstreamProtocolFailed));
            return Err(too_large());
        }
        let trace = take_upstream_trace(&mut response);
        let finish = |reason: Option<ReasonCode>| {
            if let Some(trace) = trace {
                trace.complete(reason);
            }
        };
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if bytes.len() as u64 + chunk.len() as u64 > self.max_bytes {
                        finish(Some(ReasonCode::UpstreamProtocolFailed));
                        return Err(too_large());
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => {
                    finish(Some(ReasonCode::UpstreamConnectionFailed));
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamConnectionFailed,
                        "OAuth records response unavailable",
                    ));
                }
            }
        }
        match serde_json::from_slice(&bytes) {
            Ok(value) => {
                finish(None);
                Ok(value)
            }
            Err(_) => {
                finish(Some(ReasonCode::UpstreamProtocolFailed));
                Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "OAuth records response is invalid",
                ))
            }
        }
    }
}

#[async_trait]
impl Provider for OAuthRecordsProvider {
    // The runtime performs all action, resource and credential-mode admission
    // and lends the invocation its delegated credential only after policy.
    fn resolve_scopes(
        &self,
        action: &str,
        inputs: &Value,
    ) -> Result<ResourceScopes, ProviderError> {
        let invalid = || {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "Invalid OAuth records action inputs",
            )
        };
        let object = inputs.as_object().ok_or_else(invalid)?;
        if action == "account.view" {
            return if object.is_empty() {
                Ok(BTreeMap::new())
            } else {
                Err(invalid())
            };
        }
        if !matches!(action, "record.list" | "record.view") {
            return Err(invalid());
        }
        let collection = object
            .get("collection")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if !crate::resource_policy::is_oauth_collection(collection) {
            return Err(invalid());
        }
        if object
            .keys()
            .any(|k| k != "collection" && (k != "id" || action != "record.view"))
        {
            return Err(invalid());
        }
        if action == "record.view" {
            let id = object
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(invalid());
            }
        }
        Ok(BTreeMap::from([(
            "collection".into(),
            vec![collection.into()],
        )]))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.resolve_scopes(&request.action, &request.inputs)?;
        let delegated = request.delegated_credential.as_ref().ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "OAuth records need the caller's delegated OAuth connection",
            )
        })?;
        let mut url = self
            .client
            .base()
            .join(match request.action.as_str() {
                "account.view" => "me",
                _ => "api/records",
            })
            .map_err(|_| ProviderError::error(ReasonCode::InputInvalid, "Invalid records route"))?;
        if request.action == "record.view" {
            url.path_segments_mut()
                .map_err(|_| {
                    ProviderError::error(ReasonCode::InputInvalid, "Invalid records route")
                })?
                .push(request.inputs["id"].as_str().unwrap());
        }
        if let Some(collection) = request.inputs.get("collection").and_then(Value::as_str) {
            url.query_pairs_mut().append_pair("collection", collection);
        }
        let started = Instant::now();
        let mut response = self.send(&url, &delegated.access(), 1).await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            complete_upstream_trace(&mut response, Some(ReasonCode::CredentialInvalid));
            let access = delegated.recover_after_unauthorized().await?;
            response = self.send(&url, &access, 2).await?;
        }
        let status = response.status().as_u16();
        let result = self.read_body(response).await?;
        Ok(ProviderResult {
            result,
            stream: None,
            audit: Some(json!({"provider":"oauth_stub","operation":request.action})),
            upstream_status: Some(status),
            upstream_duration_ms: Some(started.elapsed().as_millis() as u64),
            object_ids: None,
        })
    }
}
