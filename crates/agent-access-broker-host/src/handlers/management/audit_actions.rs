//! Canonical broker audit names. Route operations supply the ordinary names;
//! exceptions and non-catalog protocol events share constants with emitters.
use agent_access_core::{AuditVisibility, ResponseKind, http_route_specs};
use agent_access_provider::ResourceTypeRegistry;
use std::collections::BTreeSet;

pub(crate) const BROKER_STATUS: &str = "status";
pub(crate) const RESOURCE_TYPES: &str = "resource_types";
pub(crate) const CALLER_AUTHENTICATE: &str = "caller.authenticate";
pub(crate) const CONFIG_STATUS: &str = "config.status";
pub(crate) const CONFIG_RELOAD: &str = "config.reload";
pub(crate) const AUTH_SESSION: &str = "auth.session";
pub(crate) const AUTH_LOCAL_LOGIN: &str = "auth.local.login";
pub(crate) const AUTH_LOCAL_PASSWORD_CHANGE: &str = "auth.local.password.change";
pub(crate) const AUTH_LOGOUT: &str = "auth.logout";
pub(crate) const OIDC_LOGIN_STARTED: &str = "oidc.login.started";
pub(crate) const OIDC_LOGIN_CALLBACK: &str = "oidc.login.callback";
pub(crate) const OIDC_LOGIN_SUCCEEDED: &str = "oidc.login.succeeded";
pub(crate) const OIDC_LOGIN_FAILED: &str = "oidc.login.failed";
pub(crate) const OAUTH_CONNECTIONS_CALLBACK: &str = "oauth.connections.callback";
pub(crate) const ADMIN_TOKENS_ISSUE: &str = "admin.tokens.issue";
pub(crate) const ADMIN_TOKENS_LIST_PRINCIPAL_AGENT: &str = "admin.tokens.list_principal_agent";
pub(crate) const ADMIN_TOKENS_INSPECT_PRINCIPAL_AGENT: &str =
    "admin.tokens.inspect_principal_agent";
pub(crate) const ADMIN_TOKENS_OPTIONS_PRINCIPAL_AGENT: &str =
    "admin.tokens.options_principal_agent";
pub(crate) const ADMIN_TOKENS_ISSUE_PRINCIPAL_AGENT: &str = "admin.tokens.issue_principal_agent";
pub(crate) const ADMIN_TOKENS_REVOKE_PRINCIPAL_AGENT: &str = "admin.tokens.revoke_principal_agent";
pub(crate) const ADMIN_TOKENS_PAUSE_PRINCIPAL_AGENT: &str = "admin.tokens.pause_principal_agent";
pub(crate) const ADMIN_TOKENS_RESUME_PRINCIPAL_AGENT: &str = "admin.tokens.resume_principal_agent";
pub(crate) const ADMIN_CREDENTIALS_TARGETS: &str = "admin.credentials.targets";
pub(crate) const ADMIN_CREDENTIALS_LIST_PRINCIPAL: &str = "admin.credentials.list_principal";
pub(crate) const ADMIN_CREDENTIALS_INSPECT: &str = "admin.credentials.inspect";
pub(crate) const ADMIN_CREDENTIALS_INPUT_SCHEMA: &str = "admin.credentials.input_schema";
pub(crate) const ADMIN_CREDENTIALS_PUT: &str = "admin.credentials.put";
pub(crate) const ADMIN_CREDENTIALS_DELETE: &str = "admin.credentials.delete";
pub(crate) const ADMIN_CREDENTIALS_VERIFY: &str = "admin.credentials.verify";
pub(crate) const ADMIN_POLICY_GRANTS_INSPECT: &str = "admin.policy.grants.inspect";
pub(crate) const ADMIN_POLICY_GRANTS_VALIDATE: &str = "admin.policy.grants.validate";
pub(crate) const ADMIN_POLICY_GRANTS_CREATE: &str = "admin.policy.grants.create";
pub(crate) const ADMIN_POLICY_GRANTS_PATCH: &str = "admin.policy.grants.patch";
pub(crate) const ADMIN_POLICY_GRANTS_DELETE: &str = "admin.policy.grants.delete";
pub(crate) const ADMIN_POLICY_GRANTS_ENABLE: &str = "admin.policy.grants.enable";
pub(crate) const ADMIN_POLICY_GRANTS_DISABLE: &str = "admin.policy.grants.disable";
pub(crate) const ADMIN_POLICY_GRANTS_SUBJECTS_ADD: &str = "admin.policy.grants.subjects.add";
pub(crate) const ADMIN_POLICY_GRANTS_SUBJECTS_REMOVE: &str = "admin.policy.grants.subjects.remove";
pub(crate) const ADMIN_POLICY_SERVICE_MANAGERS_GRANT: &str = "admin.policy.service_managers.grant";
pub(crate) const ADMIN_POLICY_SERVICE_MANAGERS_REVOKE: &str =
    "admin.policy.service_managers.revoke";
pub(crate) const ADMIN_PRINCIPALS_SERVICE_LIMITS_SET: &str = "admin.principals.service_limits.set";
pub(crate) const ADMIN_PRINCIPALS_SERVICE_LIMITS_CLEAR: &str =
    "admin.principals.service_limits.clear";
pub(crate) const ADMIN_RIGHTS_GRANT: &str = "admin.rights.grant";

/// Route IDs whose actual response/audit operation differs. The mapped
/// constants are also used by the emitting handlers.
pub(crate) const CATALOG_TO_HANDLER_OPERATION: &[(&str, &str)] = &[
    ("admin.config.status", CONFIG_STATUS),
    ("admin.config.reload", CONFIG_RELOAD),
    ("admin.principals.tokens.issue", ADMIN_TOKENS_ISSUE),
    (
        "admin.principals.agent_tokens.list",
        ADMIN_TOKENS_LIST_PRINCIPAL_AGENT,
    ),
    (
        "admin.principals.agent_tokens.inspect",
        ADMIN_TOKENS_INSPECT_PRINCIPAL_AGENT,
    ),
    (
        "admin.principals.agent_tokens.options",
        ADMIN_TOKENS_OPTIONS_PRINCIPAL_AGENT,
    ),
    (
        "admin.principals.agent_tokens.issue",
        ADMIN_TOKENS_ISSUE_PRINCIPAL_AGENT,
    ),
    (
        "admin.principals.agent_tokens.revoke",
        ADMIN_TOKENS_REVOKE_PRINCIPAL_AGENT,
    ),
    (
        "admin.principals.agent_tokens.pause",
        ADMIN_TOKENS_PAUSE_PRINCIPAL_AGENT,
    ),
    (
        "admin.principals.agent_tokens.resume",
        ADMIN_TOKENS_RESUME_PRINCIPAL_AGENT,
    ),
    (
        "admin.principals.credentials.list",
        ADMIN_CREDENTIALS_LIST_PRINCIPAL,
    ),
    (
        "admin.principals.credentials.targets",
        ADMIN_CREDENTIALS_TARGETS,
    ),
    (
        "admin.principals.credentials.inspect",
        ADMIN_CREDENTIALS_INSPECT,
    ),
    (
        "admin.principals.credentials.input_schema",
        ADMIN_CREDENTIALS_INPUT_SCHEMA,
    ),
    ("admin.principals.credentials.put", ADMIN_CREDENTIALS_PUT),
    (
        "admin.principals.credentials.delete",
        ADMIN_CREDENTIALS_DELETE,
    ),
    (
        "admin.principals.credentials.verify",
        ADMIN_CREDENTIALS_VERIFY,
    ),
];

pub(crate) fn handler_operation(catalog_operation: &str) -> &str {
    CATALOG_TO_HANDLER_OPERATION
        .iter()
        .find(|(catalog, _)| *catalog == catalog_operation)
        .map_or(catalog_operation, |(_, handler)| handler)
}

// Raw discovery and ingress routes plus browser protocol events. Their
// audited failure names are not management-envelope catalog operations.
const NON_MANAGEMENT_ACTIONS: &[&str] = &[
    BROKER_STATUS,
    RESOURCE_TYPES,
    CALLER_AUTHENTICATE,
    "identity.authenticate",
    "context.authorize",
    "request.admit",
    AUTH_SESSION,
    AUTH_LOCAL_LOGIN,
    AUTH_LOCAL_PASSWORD_CHANGE,
    AUTH_LOGOUT,
    OIDC_LOGIN_STARTED,
    OIDC_LOGIN_CALLBACK,
    OIDC_LOGIN_SUCCEEDED,
    OIDC_LOGIN_FAILED,
    OAUTH_CONNECTIONS_CALLBACK,
];

/// Only these operations currently supply a service or grantRef target.
/// Other broker records never receive targetService and cannot be seen by a
/// service manager. This describes audit visibility, not invocation access.
const SERVICE_SCOPED_ACTIONS: &[&str] = &[
    ADMIN_POLICY_GRANTS_INSPECT,
    ADMIN_POLICY_GRANTS_VALIDATE,
    ADMIN_POLICY_GRANTS_CREATE,
    ADMIN_POLICY_GRANTS_PATCH,
    ADMIN_POLICY_GRANTS_DELETE,
    ADMIN_POLICY_GRANTS_ENABLE,
    ADMIN_POLICY_GRANTS_DISABLE,
    ADMIN_POLICY_GRANTS_SUBJECTS_ADD,
    ADMIN_POLICY_GRANTS_SUBJECTS_REMOVE,
    ADMIN_POLICY_SERVICE_MANAGERS_GRANT,
    ADMIN_POLICY_SERVICE_MANAGERS_REVOKE,
    ADMIN_PRINCIPALS_SERVICE_LIMITS_SET,
    ADMIN_PRINCIPALS_SERVICE_LIMITS_CLEAR,
    ADMIN_RIGHTS_GRANT,
    ADMIN_CREDENTIALS_INSPECT,
    ADMIN_CREDENTIALS_INPUT_SCHEMA,
    ADMIN_CREDENTIALS_PUT,
    ADMIN_CREDENTIALS_DELETE,
    ADMIN_CREDENTIALS_VERIFY,
];

pub(crate) fn suggestions(
    types: &ResourceTypeRegistry,
    visibility: &AuditVisibility,
) -> Vec<String> {
    if matches!(visibility, AuditVisibility::Services(_)) {
        return SERVICE_SCOPED_ACTIONS
            .iter()
            .map(|action| (*action).to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }
    // Self Activity can contain denied admin requests and records from a past
    // role. Filtering names by present invocation permissions would hide them.
    http_route_specs(types)
        .into_iter()
        .filter(|route| route.response_kind == ResponseKind::ManagementEnvelope)
        .map(|route| handler_operation(&route.operation).to_string())
        .chain(
            NON_MANAGEMENT_ACTIONS
                .iter()
                .map(|action| (*action).to_string()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_and_mapped_actions_are_canonical_and_filterable() {
        let registry = crate::backend_registry();
        let routes = http_route_specs(registry.resource_types());
        let global = suggestions(registry.resource_types(), &AuditVisibility::Global);
        for (catalog, handler) in CATALOG_TO_HANDLER_OPERATION {
            assert!(
                routes.iter().any(|route| route.operation == *catalog),
                "{catalog}"
            );
            assert!(global.iter().any(|action| action == handler), "{handler}");
            assert!(
                !global.iter().any(|action| action == catalog),
                "{catalog} is not an emitted audit name"
            );
        }
        for action in SERVICE_SCOPED_ACTIONS {
            assert!(
                global.iter().any(|candidate| candidate == action),
                "{action}"
            );
        }
        assert!(
            global
                .iter()
                .all(|action| action.len() <= 256 && agent_access_provider::is_action_name(action))
        );
        assert!(global.contains(&CONFIG_STATUS.to_string()));
        assert!(global.iter().any(|action| action == "admin.tokens.issue"));
        assert!(
            !global
                .iter()
                .any(|action| action == "admin.principals.tokens.issue")
        );
        assert!(global.contains(&OIDC_LOGIN_SUCCEEDED.to_string()));
    }
}
