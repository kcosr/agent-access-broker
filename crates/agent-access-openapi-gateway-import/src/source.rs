//! Adapter-specific document retrieval. URLs remain independently approved by core.
use crate::config::{DefinitionSource, Settings};
use agent_access_core::imports::*;
use agent_access_provider::*;
use http::header::HeaderName;
use reqwest::Method;

pub(crate) fn credential_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialInvalid,
        "gateway document credential does not match its selected authentication",
    )
}
pub(crate) fn protocol_error() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "gateway document response is invalid",
    )
}
fn authorization(
    delivery: &ImportedCredentialDelivery,
    credential: &ExecutionCredential,
) -> Result<UpstreamAuthorization, ProviderError> {
    delivery.validate().map_err(|_| credential_error())?;
    let placement = match delivery {
        ImportedCredentialDelivery::Basic => CredentialPlacement::basic(),
        ImportedCredentialDelivery::Bearer => CredentialPlacement::bearer(),
        ImportedCredentialDelivery::RawHeader { name } => {
            crate::config::parameter_header(name).map_err(|_| credential_error())?;
            CredentialPlacement::header(
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| credential_error())?,
            )
        }
        ImportedCredentialDelivery::Stdin => return Err(credential_error()),
    };
    credential
        .authorization_as(&placement)
        .map_err(|_| credential_error())
}
pub(crate) async fn read(
    settings: &Settings,
    authentication: &ImportedDiscoveryAuthentication,
    uploaded: Option<&[u8]>,
    host: &BuildContext<'_>,
) -> Result<Vec<u8>, AdapterDiscoveryError> {
    let auth = match (&settings.document_delivery, authentication) {
        (None, ImportedDiscoveryAuthentication::Anonymous) => None,
        (Some(delivery), ImportedDiscoveryAuthentication::Static(credential)) => {
            Some(authorization(delivery, credential)?)
        }
        _ => return Err(credential_error().into()),
    };
    let limit = agent_access_openapi_common::GATEWAY_MAX_DOCUMENT_BYTES
        .min(host.limits().max_upstream_response_bytes as usize);
    let url = match (&settings.source, uploaded) {
        (DefinitionSource::Upload, Some(bytes)) if bytes.len() <= limit => {
            return Ok(bytes.to_vec());
        }
        (DefinitionSource::Upload, Some(_)) => {
            return Err(ProviderError::deny(
                ReasonCode::BodySizeDenied,
                "gateway document exceeds the discovery byte limit",
            )
            .into());
        }
        (DefinitionSource::Url(url), None) => url,
        _ => {
            return Err(AdapterDiscoveryError::Configuration(
                "gateway document source does not match supplied document bytes".into(),
            ));
        }
    };
    let allowed = [url.to_string()];
    let client = UpstreamClient::build(
        UpstreamClientSpec::new(
            "imports.openapi_gateway",
            "openapi_gateway",
            url,
            EgressDeclaration::Ordinary(None),
            &allowed,
            ClientProfile::SingleAttempt,
        ),
        host.clients(),
    )
    .map_err(|_| {
        AdapterDiscoveryError::Configuration("gateway document destination is invalid".into())
    })?;
    let mut response = client
        .send(
            client.request(Method::GET, url.clone()).header(
                "Accept",
                "application/json, application/vnd.oai.openapi+json",
            ),
            UpstreamCall::new("openapi_gateway.discover").with_authorizations(auth.as_slice()),
        )
        .await
        .map_err(|error| {
            ProviderError::error(error.reason_code(), "gateway document request failed")
        })?;
    let status = response.status().as_u16();
    complete_upstream_trace(&mut response, None);
    if status != 200 {
        let reason = match status {
            401 => ReasonCode::UpstreamUnauthorized,
            403 => ReasonCode::UpstreamForbidden,
            429 => ReasonCode::UpstreamRateLimited,
            300..=399 => ReasonCode::UpstreamProtocolFailed,
            _ => ReasonCode::UpstreamFailed,
        };
        return Err(
            ProviderError::error(reason, "gateway document could not be read")
                .with_upstream(Some(status), None)
                .into(),
        );
    }
    let media = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media != "application/json"
        && !(media.starts_with("application/") && media.ends_with("+json"))
    {
        return Err(protocol_error().into());
    }
    read_bounded_body(response, limit as u64, None)
        .await
        .map_err(|error| {
            match error {
                BodyReadError::TooLarge => protocol_error(),
                _ => ProviderError::error(
                    ReasonCode::UpstreamConnectionFailed,
                    "gateway document body did not complete",
                ),
            }
            .into()
        })
}
