//! The upstream credential a Git gateway request presents.
//!
//! A static credential (a service credential, or the caller's stored token)
//! is presented as `upstream_token_auth` configures. When the caller's
//! credential connection selects OAuth, the request presents the operation's
//! OAuth lease instead: acquired after policy, then revalidated and pinned to
//! the gateway's own upstream authority immediately before each upstream
//! attempt, and presented as token material through the same
//! `upstream_token_auth`.
//!
//! Each Git HTTP request, ref discovery or pack POST, is its own operation
//! with its own lease and 401-recovery budget. The host recovers ref
//! discovery once from an upstream 401; a pack POST rejects the access it
//! presented and fails without replaying its body. A connection that needs
//! reconnecting, and access the upstream rejects, are reported as
//! `credential_invalid` (HTTP 403) with a message naming the portal
//! reconnect, never as 401, so Git neither prompts again nor has a credential
//! helper erase the Broker token.
//!
//! A static credential lent as a token profile is presented only when some
//! service this generation publishes declares the profile and none marks it
//! route-bound ([`BrokerRuntime::check_gateway_presentable`]); forwarding and
//! Git verification refuse any other before anything is sent.
use super::lookup_access::PreScopeLookup;
use super::{BrokerRuntime, PreparedGatewayOperation};
use crate::gateway_token_auth::{gateway_delegated_authorization, gateway_upstream_authorization};
use crate::oauth::OAuthError;
use crate::{GatewayConfig, IdentityContext, Selection};
use agent_access_provider::{
    CorrelationContext, DelegatedAccessError, DelegatedCredential, ExecutionAccess,
    ExecutionCredential, ProviderError, ReasonCode, UpstreamAuthority, UpstreamAuthorization,
};
use serde_json::{Value, json};

/// Where a person reconnects a credential connection.
const PORTAL_RECONNECT: &str = "under My access > Credentials in the Agent Access Broker portal";

/// The credential a prepared gateway request presents upstream.
pub(super) enum GatewayAccess {
    Static(ExecutionCredential),
    Delegated(GatewayDelegatedAccess),
}

/// The caller's OAuth lease for one gateway request.
pub(super) struct GatewayDelegatedAccess {
    credential: DelegatedCredential,
    /// The audience of the OAuth permission profile the connection selects.
    audience: String,
    /// The credential connection's display name, which failures name.
    connection: String,
}

/// The authorization one upstream attempt of a gateway request presents.
/// It exposes no material.
pub struct GatewayUpstreamPresentation {
    authorization: UpstreamAuthorization,
    /// The delegated access version presented; `None` for a static
    /// credential.
    delegated_version: Option<String>,
}

impl GatewayUpstreamPresentation {
    /// Host-only: attach with the SDK's host-only
    /// [`authorize_host_request`](agent_access_provider::host::authorize_host_request).
    pub fn authorization(&self) -> &UpstreamAuthorization {
        &self.authorization
    }

    /// Whether this presents the caller's OAuth access, whose upstream 401
    /// the host answers through
    /// [`PreparedGatewayOperation::recover_upstream_presentation`] or
    /// [`PreparedGatewayOperation::reject_upstream_presentation`]. A static
    /// credential's 401 passes through to the client unchanged.
    pub fn is_delegated(&self) -> bool {
        self.delegated_version.is_some()
    }
}

/// How the gateway answers an upstream 401 to OAuth access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayUpstreamRejection {
    /// Ref discovery was rejected again after its one recovery.
    AfterRecovery,
    /// A pack POST was rejected; its body is never replayed.
    NotReplayed,
}

impl BrokerRuntime {
    /// The credential a gateway request presents, once policy selected
    /// `credential_mode`. A `per_user` mode whose connection selects OAuth
    /// acquires the caller's lease here, after policy; any other selection
    /// reads the static credential.
    pub(super) async fn resolve_gateway_access(
        &self,
        service: &str,
        action: &str,
        credential_mode: &str,
        identity: &IdentityContext,
        correlation: &CorrelationContext,
    ) -> Result<GatewayAccess, ProviderError> {
        let descriptor = self
            .services
            .get(service)
            .map(|descriptor| &descriptor.credentials);
        let oauth = (credential_mode == "per_user")
            .then(|| self.personal_selection(service, identity))
            .flatten()
            .and_then(|(connection, selection)| match selection {
                Selection::OAuth(oauth) => Some((
                    oauth,
                    connection
                        .config
                        .display_name
                        .clone()
                        .unwrap_or_else(|| connection.id.to_owned()),
                )),
                _ => None,
            });
        let access = self
            .resolve_execution_credential_after_policy(
                descriptor,
                service,
                action,
                credential_mode,
                identity,
                correlation,
                &PreScopeLookup::None,
            )
            .await
            .map_err(|error| match &oauth {
                Some((_, connection)) => gateway_lease_failure(connection, error),
                None => error,
            })?;
        match (access, oauth) {
            (ExecutionAccess::Static(credential), _) => {
                self.check_gateway_presentable(&credential)?;
                Ok(GatewayAccess::Static(credential))
            }
            (ExecutionAccess::Delegated(credential), Some((oauth, connection))) => {
                let audience = self
                    .config
                    .oauth
                    .registrations
                    .get(&oauth.registration)
                    .and_then(|registration| registration.permission_profiles.get(&oauth.profile))
                    .map(|profile| profile.audience.clone())
                    .ok_or_else(|| {
                        ProviderError::deny(
                            ReasonCode::CredentialNotProvisioned,
                            "the gateway's OAuth permission profile is not configured",
                        )
                    })?;
                Ok(GatewayAccess::Delegated(GatewayDelegatedAccess {
                    credential,
                    audience,
                    connection,
                }))
            }
            _ => Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "the Git gateway has no upstream credential to present",
            )),
        }
    }
}

impl BrokerRuntime {
    /// Refuses a static credential a Git gateway must not present: one lent
    /// as a token profile that a service this generation publishes marks
    /// route-bound (any declaration marking it is enough), or that no published
    /// service declares. A credential without a profile is presented by its
    /// kind. Forwarding checks it before the upstream authorization is
    /// built, and Git verification before its probe.
    pub(super) fn check_gateway_presentable(
        &self,
        credential: &ExecutionCredential,
    ) -> Result<(), ProviderError> {
        let Some(profile) = credential.profile() else {
            return Ok(());
        };
        match crate::connections::profile_route_binding(
            self.services.values().map(AsRef::as_ref),
            profile,
        ) {
            Some(false) => Ok(()),
            Some(true) => Err(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "the credential's token profile is route-bound: only the service declaring it may present it, so the Git gateway refuses it",
            )),
            None => Err(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "no configured service declares the credential's token profile, so the Git gateway refuses it",
            )),
        }
    }
}

impl PreparedGatewayOperation {
    /// Host-only: the authorization the request's next upstream attempt
    /// presents for `gateway`, the configuration the request is forwarded
    /// with. OAuth access is revalidated, renewing it when stale, and pinned
    /// to `gateway`'s upstream authority immediately before it is presented.
    pub async fn upstream_presentation(
        &self,
        gateway: &GatewayConfig,
    ) -> Result<GatewayUpstreamPresentation, ProviderError> {
        match &self.access {
            GatewayAccess::Static(credential) => Ok(GatewayUpstreamPresentation {
                authorization: gateway_upstream_authorization(
                    &gateway.upstream_token_auth,
                    credential,
                )?,
                delegated_version: None,
            }),
            GatewayAccess::Delegated(delegated) => delegated.present(gateway).await,
        }
    }

    /// Host-only: after the upstream answered ref discovery's OAuth access
    /// with 401, replaces that access once, reusing a successor another
    /// request already obtained, and presents the replacement. The request's
    /// lease recovers at most once.
    pub async fn recover_upstream_presentation(
        &self,
        gateway: &GatewayConfig,
    ) -> Result<GatewayUpstreamPresentation, ProviderError> {
        let GatewayAccess::Delegated(delegated) = &self.access else {
            return Err(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "a static gateway credential is not recovered",
            ));
        };
        delegated
            .credential
            .recover_after_unauthorized()
            .await
            .map_err(|error| gateway_lease_failure(&delegated.connection, error))?;
        delegated.present(gateway).await
    }

    /// Host-only: the failure for an upstream 401 to `presentation`, after
    /// rejecting the OAuth access version it presented so later requests
    /// renew it. Rejecting a version another request already replaced
    /// changes nothing. The failure is `credential_invalid` (HTTP 403) and
    /// names the portal reconnect.
    pub fn reject_upstream_presentation(
        &self,
        presentation: &GatewayUpstreamPresentation,
        rejection: GatewayUpstreamRejection,
    ) -> ProviderError {
        let GatewayAccess::Delegated(delegated) = &self.access else {
            return ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "the upstream rejected the gateway credential",
            );
        };
        if let Some(version) = &presentation.delegated_version {
            // A failure to record the rejection leaves the access in place
            // until it expires; the request fails either way.
            let _ = delegated.credential.mark_rejected(version);
        }
        let connection = &delegated.connection;
        ProviderError::deny(
            ReasonCode::CredentialInvalid,
            match rejection {
                GatewayUpstreamRejection::AfterRecovery => format!(
                    "{connection} rejected the connected account's renewed access; reconnect it {PORTAL_RECONNECT}, then retry"
                ),
                GatewayUpstreamRejection::NotReplayed => format!(
                    "{connection} rejected the connected account's access and the Git request was not replayed; retry, and if it is rejected again, reconnect it {PORTAL_RECONNECT}"
                ),
            },
        )
    }

    /// `audit` with `gateway.credentialMethod`, how the caller's credential
    /// connection authenticated the request: `oauth` or `token`. Requests on
    /// service credentials add nothing.
    pub(super) fn with_credential_method(&self, mut audit: Value) -> Value {
        if self.credential_mode == "per_user"
            && let Some(gateway) = audit.get_mut("gateway").and_then(Value::as_object_mut)
        {
            let method = match self.access {
                GatewayAccess::Static(_) => "token",
                GatewayAccess::Delegated(_) => "oauth",
            };
            gateway.insert("credentialMethod".to_string(), json!(method));
        }
        audit
    }

    /// `error` with [`Self::with_credential_method`] applied to its audit.
    pub(super) fn with_error_credential_method(&self, mut error: ProviderError) -> ProviderError {
        if let Some(audit) = error.audit.take() {
            error.audit = Some(Box::new(self.with_credential_method(*audit)));
        }
        error
    }
}

impl GatewayDelegatedAccess {
    async fn present(
        &self,
        gateway: &GatewayConfig,
    ) -> Result<GatewayUpstreamPresentation, ProviderError> {
        let access = self
            .credential
            .revalidated_access_for(&gateway_target(&gateway.upstream_base_url)?, &self.audience)
            .await
            .map_err(|error| match error {
                DelegatedAccessError::Revalidation(failure) => {
                    gateway_lease_failure(&self.connection, failure)
                }
                _ => ProviderError::deny(
                    ReasonCode::CredentialInvalid,
                    "the OAuth access is not for the gateway's upstream",
                ),
            })?;
        Ok(GatewayUpstreamPresentation {
            authorization: gateway_delegated_authorization(&gateway.upstream_token_auth, &access)?,
            delegated_version: Some(access.version().to_owned()),
        })
    }
}

/// The target a gateway pins OAuth access to: the normalized origin and
/// instance path of its own `upstream_base_url`. Offline validation already
/// requires a connection's OAuth registration to grant exactly this
/// authority, through the registration's dialect, so the pin holds for any
/// dialect without core knowing it.
fn gateway_target(upstream_base_url: &str) -> Result<String, ProviderError> {
    let authority = UpstreamAuthority::from_base_url(upstream_base_url).map_err(|_| {
        ProviderError::error(
            ReasonCode::GatewayUpstreamDenied,
            "gateway upstream base URL is invalid",
        )
    })?;
    Ok(format!(
        "{}{}",
        authority.origin(),
        authority.instance_path()
    ))
}

/// A lease failure as the gateway reports it: a connection that needs
/// reconnecting, including after a refresh whose outcome is unknown, names
/// the portal reconnect. Other failures, such as refresh in progress or
/// throttled, keep their classification and retry metadata.
fn gateway_lease_failure(connection: &str, error: ProviderError) -> ProviderError {
    let reconnect = error.reason_code() == ReasonCode::CredentialInvalid
        && [
            OAuthError::ReconnectRequired.code(),
            OAuthError::RefreshUncertain.code(),
        ]
        .contains(&error.message.as_str());
    if !reconnect {
        return error;
    }
    ProviderError::deny(
        ReasonCode::CredentialInvalid,
        format!(
            "{connection} has no usable connected account; connect or reconnect it {PORTAL_RECONNECT}, then retry"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::Decision;

    #[test]
    fn only_reconnect_states_name_the_portal_reconnect() {
        for state in [OAuthError::ReconnectRequired, OAuthError::RefreshUncertain] {
            let failure = gateway_lease_failure(
                "GitLab",
                ProviderError::deny(ReasonCode::CredentialInvalid, state.code()),
            );
            assert_eq!(failure.decision(), Decision::Deny);
            assert_eq!(failure.reason_code(), ReasonCode::CredentialInvalid);
            assert_eq!(
                failure.message,
                "GitLab has no usable connected account; connect or reconnect it under My access > Credentials in the Agent Access Broker portal, then retry"
            );
        }
        for kept in [
            ProviderError::error(
                ReasonCode::ConcurrencyLimited,
                OAuthError::RefreshBusy.code(),
            ),
            ProviderError::deny(ReasonCode::CredentialInvalid, OAuthError::Storage.code()),
            ProviderError::deny(
                ReasonCode::VersionConflict,
                OAuthError::ConsentPending.code(),
            ),
        ] {
            let message = kept.message.clone();
            assert_eq!(gateway_lease_failure("GitLab", kept).message, message);
        }
    }

    #[test]
    fn the_pin_is_the_gateway_upstream_instance() {
        for (base, target) in [
            (
                "https://GitLab.example.com:443/",
                "https://gitlab.example.com",
            ),
            (
                "https://gitlab.example.com/git/root/",
                "https://gitlab.example.com/git/root",
            ),
        ] {
            assert_eq!(gateway_target(base).unwrap(), target);
        }
        assert_eq!(
            gateway_target("not a url").unwrap_err().reason_code(),
            ReasonCode::GatewayUpstreamDenied
        );
    }
}
