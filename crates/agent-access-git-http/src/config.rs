use agent_access_provider::{
    ActionDescriptor, CredentialDescriptor, GatewayConfig, GatewayProtocol, GatewayServiceContext,
    ProviderBuildError, ResourceScopeCapabilities, ServiceDescriptor, ServiceSurface,
    UpstreamAuthority,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GitModuleConfig {
    pub(crate) git: Option<GitConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GitConfig {
    #[serde(default)]
    pub allow_fetch: bool,
    #[serde(default)]
    pub allow_push: bool,
    #[serde(default)]
    pub deny_ref_patterns: Vec<String>,
    #[serde(default = "default_deny_delete_refs")]
    pub deny_delete_refs: bool,
    pub receive_pack_prefix_max_bytes: Option<u64>,
}

fn default_deny_delete_refs() -> bool {
    true
}

pub(crate) fn validate(service: &str, git: &GitConfig, errors: &mut Vec<String>) {
    if !git.allow_fetch && !git.allow_push {
        errors.push(format!(
            "gateways.{service}.git must enable allow_fetch or allow_push"
        ));
    }
    if git.receive_pack_prefix_max_bytes == Some(0) {
        errors.push(format!(
            "gateways.{service}.git.receive_pack_prefix_max_bytes must be non-zero"
        ));
    }
    let mut patterns = BTreeSet::new();
    for pattern in &git.deny_ref_patterns {
        if !patterns.insert(pattern.clone()) {
            errors.push(format!(
                "gateways.{service}.git.deny_ref_patterns contains duplicate pattern {pattern}"
            ));
        }
        if !is_git_ref_pattern(pattern) {
            errors.push(format!(
                "gateways.{service}.git.deny_ref_patterns contains invalid pattern {pattern}"
            ));
        }
    }
}

fn is_git_ref_pattern(value: &str) -> bool {
    let value = value.strip_suffix("/**").unwrap_or(value);
    if value.is_empty()
        || !value.starts_with("refs/")
        || value.contains('\\')
        || value.contains("//")
        || value.contains("..")
        || value.contains('*')
        || value.chars().any(char::is_control)
    {
        return false;
    }
    for segment in value.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return false;
        }
    }
    true
}

impl GatewayConfig for GitModuleConfig {
    fn validate(&self, context: &GatewayServiceContext, errors: &mut Vec<String>) {
        let Some(git) = self.git.as_ref() else {
            errors.push(format!(
                "gateways.{}.git is required for git_http",
                context.service
            ));
            return;
        };
        validate(&context.service, git, errors);
        for mode in &context.auth_modes {
            if mode != "basic_broker_token" {
                errors.push(format!(
                    "gateways.{}.auth_modes contains unsupported mode {mode}",
                    context.service
                ));
            }
        }
    }

    fn descriptor(&self, context: &GatewayServiceContext) -> ServiceDescriptor {
        let git_action = |action: &str, description: &str| {
            ActionDescriptor::new(
                action,
                description,
                json!({
                    "type": "object",
                    "additionalProperties": false
                }),
            )
            .scope("repository")
            .credential_modes(context.credential_modes.iter().cloned())
        };
        let mut actions = Vec::new();
        if self.git.as_ref().is_some_and(|git| git.allow_fetch) {
            actions.push(
                git_action(
                    "repo.fetch",
                    "Fetch from a Git repository through the broker gateway",
                )
                .read_only(),
            );
        }
        if self.git.as_ref().is_some_and(|git| git.allow_push) {
            actions.push(git_action(
                "repo.push",
                "Push to a Git repository through the broker gateway",
            ));
        }
        let per_user = context
            .credential_modes
            .iter()
            .any(|mode| mode == "per_user");
        // Verifying a Git credential reads one repository's refs. A personal
        // credential connection may also select OAuth, whose access the gateway
        // presents like a token.
        let credentials = if per_user {
            CredentialDescriptor::default()
                .verification_input("repository")
                .profile("git-basic-api-token", "basic_api_token")
                .profile("git-bearer-token", "bearer_token")
                .delegated(if self.git.as_ref().is_some_and(|git| git.allow_push) {
                    "Lets agents fetch and push Git repositories as your account."
                } else {
                    "Lets agents fetch Git repositories as your account."
                })
        } else {
            CredentialDescriptor::default().verification_input("repository")
        };
        let credentials = if self.git.as_ref().is_some_and(|git| git.allow_fetch) {
            credentials
        } else {
            credentials.without_verification()
        };
        let descriptor = ServiceDescriptor::new(&context.service, context.display_name.clone())
            .with_surface(ServiceSurface::Gateway {
                kind: "git_http".to_string(),
                broker_hosts: context.broker_hosts.clone(),
            })
            .with_resource_scopes(BTreeMap::from([(
                "repository".to_string(),
                ResourceScopeCapabilities::new(
                    agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
                    vec![
                        "exact".to_string(),
                        "namespace".to_string(),
                        "all".to_string(),
                    ],
                ),
            )]))
            .with_actions(actions)
            .with_credentials(credentials);
        match UpstreamAuthority::from_base_url(&context.upstream_base_url) {
            Ok(authority) => descriptor.with_upstream_authority(authority),
            Err(_) => descriptor,
        }
    }

    fn build(
        &self,
        context: &GatewayServiceContext,
    ) -> Result<Arc<dyn GatewayProtocol>, ProviderBuildError> {
        let mut errors = Vec::new();
        self.validate(context, &mut errors);
        if let Some(error) = errors.first() {
            return Err(ProviderBuildError::invalid(error.clone()));
        }
        let git = self.git.clone().ok_or_else(|| {
            ProviderBuildError::invalid(format!(
                "gateways.{}.git is required for git_http",
                context.service
            ))
        })?;
        Ok(Arc::new(crate::GitProtocol { git }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_configuration_is_strict_and_keeps_defaults() {
        let module: GitModuleConfig = toml::from_str("[git]\nallow_fetch = true").unwrap();
        let git = module.git.unwrap();
        assert!(git.allow_fetch);
        assert!(!git.allow_push);
        assert!(git.deny_delete_refs);
        assert!(git.deny_ref_patterns.is_empty());
        assert_eq!(git.receive_pack_prefix_max_bytes, None);
        for source in [
            "allow_fetch = true",
            "[git]\nallow_fetch = true\nother = 1",
            "[other]\nx = 1",
        ] {
            assert!(
                toml::from_str::<GitModuleConfig>(source).is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn invalid_configuration_keeps_specific_service_diagnostics() {
        let git: GitConfig = toml::from_str("receive_pack_prefix_max_bytes = 0\ndeny_ref_patterns = ['refs/heads/**', 'refs/heads/**', 'refs/**/x']").unwrap();
        let mut errors = Vec::new();
        validate("example", &git, &mut errors);
        assert_eq!(
            errors,
            [
                "gateways.example.git must enable allow_fetch or allow_push",
                "gateways.example.git.receive_pack_prefix_max_bytes must be non-zero",
                "gateways.example.git.deny_ref_patterns contains duplicate pattern refs/heads/**",
                "gateways.example.git.deny_ref_patterns contains invalid pattern refs/**/x",
            ]
        );
    }
}
