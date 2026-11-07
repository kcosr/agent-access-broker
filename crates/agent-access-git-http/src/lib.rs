//! Git smart HTTP protocol support for the Agent Access Broker gateway SDK.
//! The host owns transport, identity, policy, credentials and audit completion.
mod classify;
mod config;
mod probe;
mod receive_pack;
#[cfg(test)]
mod tests;

use agent_access_provider::{
    GatewayBody, GatewayBodyError, GatewayBodyFrame, GatewayClassification, GatewayForwardPlan,
    GatewayProtocol, GatewayRegistration, GatewayReplayProfile, GatewayRequest, GatewayRequestHead,
    GatewayRequestKind, GatewayResponseProfile, GatewayVerificationProbe, ProviderError,
    ReasonCode,
};
use async_trait::async_trait;
use classify::GitRequestKind;
use config::{GitConfig, GitModuleConfig};
use http::{HeaderMap, Uri, header::CONTENT_LENGTH};
use std::sync::Arc;

/// Selects Git smart HTTP gateway support. Service identities and hosts remain
/// deployment configuration; the durable repository resource type is host-owned.
pub static GIT_HTTP_GATEWAY: GatewayRegistration = GatewayRegistration::new(
    agent_access_provider::module_metadata!(),
    "git_http",
    parse_config,
)
.with_request_kinds(&[
    GatewayRequestKind::exempt("upload-pack-discovery"),
    GatewayRequestKind::counted("upload-pack-post"),
    GatewayRequestKind::exempt("receive-pack-discovery"),
    GatewayRequestKind::counted("receive-pack-post"),
])
.with_audit_key("git");

fn parse_config(
    value: toml::Value,
) -> Result<Arc<dyn agent_access_provider::GatewayConfig>, String> {
    let config: GitModuleConfig = value
        .try_into()
        .map_err(|error: toml::de::Error| error.to_string())?;
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct GitProtocol {
    git: GitConfig,
}

impl GatewayProtocol for GitProtocol {
    fn classify(
        &self,
        head: GatewayRequestHead<'_>,
    ) -> Result<GatewayClassification, ProviderError> {
        let uri: Uri = head.path_and_query().parse().map_err(|_| {
            ProviderError::deny(ReasonCode::GatewayRuleNotFound, "gateway path is invalid")
        })?;
        let classified = classify::classify(&self.git, head.method(), &uri, head.headers())?;
        let kind = classified.git_request_kind;
        let target = kind.relative_target(&classified.resource_scopes)?;
        Ok(GatewayClassification::new(
            kind.action(),
            classified.resource_scopes,
            kind.name(),
            Box::new(GitRequest {
                git: self.git.clone(),
                kind,
                target,
                headers: head.headers().clone(),
            }),
        ))
    }

    fn verification(
        &self,
        input: Option<&str>,
    ) -> Result<Option<Box<dyn GatewayVerificationProbe>>, ProviderError> {
        if !self.git.allow_fetch {
            return Ok(None);
        }
        Ok(Some(Box::new(probe::GitProbe::new(input)?)))
    }
}

struct GitRequest {
    git: GitConfig,
    kind: GitRequestKind,
    target: String,
    headers: HeaderMap,
}

#[async_trait]
impl GatewayRequest for GitRequest {
    async fn preflight(
        self: Box<Self>,
        mut body: GatewayBody,
    ) -> Result<GatewayForwardPlan, ProviderError> {
        let encoding = classify::validate_representation_headers(&self.headers, self.kind)?;
        let length = self
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u128>().ok());
        if length.is_some_and(|length| length > body.max_bytes() as u128) {
            let error = body_error(GatewayBodyError::TooLarge, self.kind.is_receive_pack_post());
            return Err(if self.kind.is_receive_pack_post() {
                receive_pack::ReceivePackParser::new(&self.git, body.max_bytes())
                    .attach_audit(error)
            } else {
                error
            });
        }
        let audit = if self.kind.is_receive_pack_post() {
            let mut parser = receive_pack::ReceivePackParser::new(&self.git, body.max_bytes());
            while !parser.complete() {
                let frame = body
                    .next_frame()
                    .await
                    .map_err(|error| parser.attach_audit(body_error(error, true)))?;
                match frame {
                    Some(GatewayBodyFrame::Data(bytes)) => parser.push(&bytes)?,
                    Some(GatewayBodyFrame::Trailers) => parser.trailers()?,
                    None => parser.end()?,
                    _ => return Err(parser.attach_audit(body_error(GatewayBodyError::Read, true))),
                }
            }
            Some(parser.audit())
        } else if !self.kind.is_pack_post() {
            if length.is_some_and(|length| length > 0) {
                return Err(ProviderError::deny(
                    ReasonCode::GatewayRequestBodyDenied,
                    "gateway GET requests must not include a body",
                ));
            }
            while let Some(frame) = body
                .next_frame()
                .await
                .map_err(|error| body_error(error, false))?
            {
                match frame {
                    GatewayBodyFrame::Data(bytes) if !bytes.is_empty() => {
                        return Err(ProviderError::deny(
                            ReasonCode::GatewayRequestBodyDenied,
                            "gateway GET requests must not include a body",
                        ));
                    }
                    GatewayBodyFrame::Data(_) => {}
                    GatewayBodyFrame::Trailers => {
                        return Err(ProviderError::deny(
                            ReasonCode::GatewayRequestBodyDenied,
                            "gateway GET requests must not include trailers",
                        ));
                    }
                    _ => return Err(body_error(GatewayBodyError::Read, false)),
                }
            }
            None
        } else {
            None
        };
        let headers = classify::request_headers(&self.headers, self.kind, encoding)?;
        let mut plan = GatewayForwardPlan::new(self.kind.method(), self.target, body)
            .with_headers(headers)
            .with_response(
                GatewayResponseProfile::new(vec!["content-type".into()]).bounded_retry_after(),
            )
            .with_replay(if self.kind.is_pack_post() {
                GatewayReplayProfile::Never
            } else {
                GatewayReplayProfile::BodylessCredentialRecovery
            });
        if let Some(audit) = audit {
            plan = plan.with_audit(audit);
        }
        Ok(plan)
    }
}

fn body_error(error: GatewayBodyError, receive_pack: bool) -> ProviderError {
    match error {
        GatewayBodyError::TooLarge => ProviderError::deny(
            ReasonCode::GatewayRequestCapExceeded,
            "gateway request body exceeds configured cap",
        ),
        GatewayBodyError::Timeout => ProviderError::deny(
            ReasonCode::GatewayRequestBodyDenied,
            "gateway request body read timed out",
        ),
        GatewayBodyError::IdleTimeout if receive_pack => ProviderError::deny(
            ReasonCode::GatewayRequestBodyDenied,
            "gateway git receive-pack request body read timed out",
        ),
        GatewayBodyError::IdleTimeout => ProviderError::error(
            ReasonCode::UpstreamTimeout,
            "gateway request body read timed out",
        ),
        _ if receive_pack => ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack request body read failed",
        ),
        _ => ProviderError::deny(
            ReasonCode::GatewayRequestBodyDenied,
            "gateway request body read failed",
        ),
    }
}
