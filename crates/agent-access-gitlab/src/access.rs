//! The credential each GitLab request presents: a static token, or the
//! operation's delegated (OAuth) credential pinned to this GitLab instance.
//!
//! Delegated access is never held across requests. Immediately before each
//! request the lease is revalidated and its access pinned to the instance
//! target and the `gitlab` audience, so a refresh between requests (by this
//! operation or another) is picked up, and access for another instance or
//! audience is refused before anything is sent. GitLab answering a request
//! with 401 authenticated nothing, so applied nothing: exactly the access
//! version that request presented is marked rejected, and its first attempt
//! may ask the lease to recover and repeat once. The lease holds the
//! operation's one recovery budget, shared by its lookups and its execution,
//! and decides whether recovery is still possible. A static token's 401 is
//! reported as before and never repeated.
use super::*;
use crate::oauth::GITLAB_OAUTH_AUDIENCE;

/// The credential one GitLab request presents. Clones share a delegated
/// credential's lease and its one recovery budget.
#[derive(Clone, Debug)]
pub struct GitlabCredential(Material);

#[derive(Clone, Debug)]
enum Material {
    Static(ExecutionCredential),
    /// The operation's delegated credential and the OAuth target of the
    /// GitLab instance the provider acts on, or `None` when the provider's
    /// `api_base_url` names no instance.
    Delegated {
        credential: DelegatedCredential,
        target: Option<Arc<str>>,
    },
}

/// The authorization one attempt presents, and the delegated access
/// version it carries.
pub(crate) struct Presented {
    pub(crate) authorization: UpstreamAuthorization,
    version: Option<String>,
}

impl GitlabCredential {
    /// A static token: the service's shared credential or the caller's
    /// stored token. Only `bearer_token` reaches GitLab.
    pub(crate) fn from_static(credential: ExecutionCredential) -> Self {
        Self(Material::Static(credential))
    }

    /// The operation's delegated credential, pinned to `target`, the OAuth
    /// target of the GitLab instance the provider acts on.
    pub(crate) fn delegated(credential: DelegatedCredential, target: Option<Arc<str>>) -> Self {
        Self(Material::Delegated { credential, target })
    }

    /// The static token this credential presents, or `None` for delegated
    /// access. A backend reads its kind or, in tests, compares it; it never
    /// reads the material.
    pub fn static_credential(&self) -> Option<&ExecutionCredential> {
        match &self.0 {
            Material::Static(credential) => Some(credential),
            Material::Delegated { .. } => None,
        }
    }

    /// The authorization for the next request. Delegated access is
    /// revalidated and pinned to the instance target and the `gitlab`
    /// audience now; a lease failure passes through unchanged, and access
    /// for another instance or audience fails before anything is sent.
    pub(crate) async fn present(&self) -> Result<Presented, GitlabBackendError> {
        match &self.0 {
            Material::Static(credential) => Ok(Presented {
                authorization: gitlab_authorization(credential)?,
                version: None,
            }),
            Material::Delegated { credential, target } => {
                let target = target.as_deref().ok_or_else(instance_mismatch)?;
                let access = credential
                    .revalidated_access_for(target, GITLAB_OAUTH_AUDIENCE)
                    .await
                    .map_err(|error| match error {
                        DelegatedAccessError::Revalidation(failure) => {
                            GitlabBackendError::Credential(failure)
                        }
                        _ => instance_mismatch(),
                    })?;
                Ok(Presented {
                    authorization: access.authorization(),
                    version: Some(access.version().to_owned()),
                })
            }
        }
    }

    /// Handles GitLab's 401 answer to delegated `presented` access: marks
    /// exactly the presented version rejected, so no later request presents
    /// it. With a `replay` of the request (its first attempt, which can be
    /// sent again) it asks the lease to recover and returns the replay to
    /// send once with renewed access. The lease's own failure, including an
    /// operation that already recovered, passes through unchanged. A 401
    /// that cannot be repeated requires reconnecting if it recurs.
    pub(crate) async fn rejected<T>(
        &self,
        presented: &Presented,
        replay: Option<T>,
    ) -> Result<T, GitlabBackendError> {
        let (Material::Delegated { credential, .. }, Some(version)) =
            (&self.0, presented.version.as_deref())
        else {
            return Err(GitlabBackendError::Unauthorized);
        };
        credential
            .mark_rejected(version)
            .map_err(GitlabBackendError::Credential)?;
        let Some(replay) = replay else {
            return Err(GitlabBackendError::Credential(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "GitLab rejected the connected GitLab account's access again; reconnect GitLab in the Broker portal if this repeats",
            )));
        };
        credential
            .recover_after_unauthorized()
            .await
            .map_err(GitlabBackendError::Credential)?;
        Ok(replay)
    }
}

impl Presented {
    /// Whether the authorization carries delegated (OAuth) access.
    pub(crate) fn is_delegated(&self) -> bool {
        self.version.is_some()
    }
}

/// The lease's access is not for the GitLab instance this provider acts on.
fn instance_mismatch() -> GitlabBackendError {
    GitlabBackendError::Credential(ProviderError::deny(
        ReasonCode::CredentialInvalid,
        "the GitLab OAuth connection does not grant access to this GitLab instance",
    ))
}

impl GitlabProvider {
    /// The execution material the host selected, as GitLab presents it.
    pub(crate) fn execution_credential(
        &self,
        request: &ProviderInvocation,
    ) -> Result<GitlabCredential, ProviderError> {
        match request.execution() {
            ExecutionAccess::Static(credential) => {
                Ok(GitlabCredential::from_static(credential.clone()))
            }
            ExecutionAccess::Delegated(credential) => Ok(self.delegated(credential)),
            _ => Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected credential mode is not provisioned",
            )),
        }
    }

    /// The lookup access of an admitted invocation.
    pub(crate) fn lookup_credential(
        &self,
        request: &ProviderInvocation,
    ) -> Result<GitlabCredential, ProviderError> {
        self.required_lookup_credential(request.lookup_access())
    }

    /// The lookup access the host selected: a static token, or the
    /// operation's delegated credential, whose lease and recovery budget
    /// execution shares. No access, or a kind GitLab does not know, fails
    /// closed.
    pub(crate) fn required_lookup_credential(
        &self,
        lookup_access: Option<&LookupAccess>,
    ) -> Result<GitlabCredential, ProviderError> {
        match lookup_access {
            Some(LookupAccess::Static(credential)) => {
                Ok(GitlabCredential::from_static(credential.clone()))
            }
            Some(LookupAccess::Delegated(credential)) => Ok(self.delegated(credential)),
            None => Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "lookup credential is not provisioned",
            )),
            Some(_) => Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected lookup credential is unavailable",
            )),
        }
    }

    fn delegated(&self, credential: &DelegatedCredential) -> GitlabCredential {
        GitlabCredential::delegated(credential.clone(), self.instance_target.clone())
    }
}

#[cfg(test)]
mod tests;
