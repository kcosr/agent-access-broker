use crate::protocol::Operation;
use agent_access_openapi_common::{GATEWAY_COMMON_RESPONSE_HEADERS, GatewayPathMatch};
use agent_access_provider::{
    GatewayBody, GatewayBodyError, GatewayBodyFrame, GatewayForwardPlan, GatewayReplayProfile,
    GatewayRequest, GatewayResponseProfile, GatewayResponseValidator, GatewayStatusHeaders,
    GatewayStatusMatch, ProviderError, ReasonCode,
};
use async_trait::async_trait;
use http::{HeaderMap, HeaderValue, Method, header::ACCEPT_ENCODING};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};

// Deliberately no Debug: these values can carry caller secrets.
pub(crate) struct Request {
    pub operation: Arc<Operation>,
    pub path: String,
    pub parameters: BTreeMap<String, String>,
    pub raw_query: String,
    pub headers: HeaderMap,
    pub upstream_base: String,
    pub manifest_generation: u64,
}

#[async_trait]
impl GatewayRequest for Request {
    async fn preflight(
        self: Box<Self>,
        mut body: GatewayBody,
    ) -> Result<GatewayForwardPlan, ProviderError> {
        let plan = &self.operation.plan;
        let matched = GatewayPathMatch {
            template: &plan.path,
            canonical_path: self.path,
            parameters: self.parameters,
            route: None,
        };
        // Values are checked only after host admission. They never change the
        // already classified action or its empty resource scope.
        let mut validated = plan
            .validate_request_parameters(&matched, Some(&self.raw_query), &self.headers)
            // The shared profile returns only bounded, value-free literals.
            .map_err(|message| ProviderError::deny(ReasonCode::InputInvalid, message))?;
        // Caller negotiation is outside this finite profile. The host sends
        // this fixed preference and preserves encoded bytes if it is ignored.
        validated
            .headers
            .insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        let present = loop {
            match body.next_frame().await.map_err(body_error)? {
                // The SDK bounds consecutive empty frames and latches a read
                // error; no second inspection budget or retained copy is needed.
                Some(GatewayBodyFrame::Data(bytes)) if bytes.is_empty() => {}
                Some(GatewayBodyFrame::Data(_)) => break true,
                None => break false,
                Some(_) => {
                    return Err(ProviderError::deny(
                        ReasonCode::GatewayRequestBodyDenied,
                        "gateway request trailers are unsupported",
                    ));
                }
            }
        };
        // Header multiplicity and value bounds were checked with the other
        // protocol fields above. Inspected bytes remain in the SDK replay body.
        let content_type = self
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok());
        plan.validate_body(present, content_type)
            .map_err(|message| {
                ProviderError::deny(ReasonCode::GatewayRequestBodyDenied, message)
            })?;

        let mut status_headers = Vec::new();
        for (status, response) in &plan.responses {
            let status = if status == "default" {
                GatewayStatusMatch::Default
            } else if let Some(class) = status.strip_suffix("XX") {
                GatewayStatusMatch::Class(class.parse().map_err(|_| invalid_plan())?)
            } else {
                GatewayStatusMatch::Exact(status.parse().map_err(|_| invalid_plan())?)
            };
            status_headers.push(GatewayStatusHeaders::new(
                status,
                response
                    .headers
                    .iter()
                    .filter(|header| !header.name.eq_ignore_ascii_case("retry-after"))
                    .map(|header| header.name.to_ascii_lowercase())
                    .collect(),
            ));
        }
        let response = GatewayResponseProfile::new(
            GATEWAY_COMMON_RESPONSE_HEADERS
                .iter()
                .filter(|name| **name != "retry-after")
                .map(|name| (*name).to_owned())
                .collect(),
        )
        .with_status_headers(status_headers)
        .translate_unauthorized()
        .reject_redirects()
        .preserve_content_length()
        .bounded_retry_after()
        .with_validator(self.operation.clone());
        let audit = json!({
            "kind": "openapi_gateway",
            "source": plan.source,
            "method": plan.method,
            "pathTemplate": plan.path,
            "upstreamBase": self.upstream_base,
            "acceptedPlanHash": self.operation.accepted_hash,
            "routeManifestGeneration": self.manifest_generation,
            "parametersPresent": validated.present_parameters,
        });
        Ok(GatewayForwardPlan::new(
            Method::from_bytes(plan.method.as_bytes()).map_err(|_| invalid_plan())?,
            validated.relative_target,
            body,
        )
        .with_headers(validated.headers)
        .with_response(response)
        .with_replay(GatewayReplayProfile::ConfirmedUnprocessed)
        .with_audit(audit)
        .with_audit_target(plan.path.clone()))
    }
}

impl GatewayResponseValidator for Operation {
    fn validate(&self, status: u16, headers: &HeaderMap) -> Result<HeaderMap, ProviderError> {
        // The host alone interprets Retry-After, including duplicate/invalid
        // values, its 429-only rule and its whole-second upper bound.
        let mut ordinary = headers.clone();
        ordinary.remove("retry-after");
        self.plan.response_headers(status, &ordinary).map_err(|_| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "upstream response headers do not match the accepted gateway operation",
            )
        })
    }
}

fn invalid_plan() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "gateway operation profile is invalid",
    )
}

fn body_error(error: GatewayBodyError) -> ProviderError {
    match error {
        GatewayBodyError::TooLarge => ProviderError::deny(
            ReasonCode::BodySizeDenied,
            "gateway request body exceeds its byte limit",
        ),
        GatewayBodyError::Timeout | GatewayBodyError::IdleTimeout => ProviderError::deny(
            ReasonCode::GatewayRequestBodyDenied,
            "gateway request body timed out",
        ),
        _ => ProviderError::deny(
            ReasonCode::GatewayRequestBodyDenied,
            "gateway request body could not be read",
        ),
    }
}
