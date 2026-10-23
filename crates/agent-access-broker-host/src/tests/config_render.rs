//! Renders a [`BrokerConfig`] that a host test builds in Rust as the TOML
//! document a test broker starts from. Every struct is destructured
//! exhaustively, so a new configuration field fails to compile here until it
//! is rendered, and [`super::ConfigDoc::from_config`] checks that the
//! document parses back to exactly the same configuration.
use agent_access_cloudbees_ci::{CloudbeesCiControllerConfig, CloudbeesCiProviderConfig};
use agent_access_confluence::{ConfluenceContentConfig, ConfluenceProviderConfig};
use agent_access_conformance::ConformanceConfig;
use agent_access_core::{
    AttributionConfig, AuditConfig, AuditDurability, BrokerConfig, BrokerTokenTtlOption,
    BrokerTokensConfig, BrowserAuthConfig, CommandImportConfig, ConnectionConfig,
    ConnectionOAuthConfig, CredentialConfig, CredentialEncryptionConfig,
    CredentialEncryptionKeyConfig, CredentialsConfig, DeploymentConfig, ExecutionContextConfig,
    GatewayConfig, GatewayGitConfig, GatewayUpstreamTokenAuth, IdentityConfig, IdentityGroupConfig,
    IdentitySourceConfig, ImportsConfig, InitialAdminConfig, InvocationLimitConfig,
    InvocationLimitsConfig, LimitsConfig, LocalPasswordConfig, ManagedStoreConfig,
    ManagementConfig, McpConfig, MicrosoftOidcConfig, NetworkConfig, OAuthConfig, OidcConfig,
    OutboundTlsConfig, OutboundTlsTrustMode, PolicyConfig, PolicyGrantConfig, PortalConfig,
    PrincipalInvocationLimitConfig, ProvidersConfig, ResourceDefinition, ResourceGroupDefinition,
    ResourceSelection, StaticPrincipalConfig, TrustedCallerConfig, TrustedCallerContextMode,
};
use agent_access_fake::{FakeProviderConfig, OAuthStubProviderConfig};
use agent_access_gitlab::{
    GitlabContentConfig, GitlabProviderConfig, GitlabProvisioningConfig, GitlabSearchConfig,
    GitlabSearchEngineConfig, GitlabSearchEnginesConfig, GitlabUploadLimitsConfig,
    GitlabWebhooksConfig,
};
use agent_access_gmail::GmailConfig;
use agent_access_jira::{
    JiraCommentVisibilityConfig, JiraCommentsConfig, JiraContentConfig, JiraIssueLinksConfig,
    JiraProviderConfig,
};
use agent_access_provider::{AttachmentLimitsConfig, EgressProxyConfig, SearchLimitsConfig};
use agent_access_teams::TeamsConfig;
use std::collections::BTreeMap;
use toml::{Table, Value};

/// A TOML table built field by field; absent options are omitted.
#[derive(Default)]
struct Fields(Table);

impl Fields {
    fn put(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.0.insert(key.to_string(), value.into());
        self
    }

    fn opt(self, key: &str, value: Option<impl Into<Value>>) -> Self {
        match value {
            Some(value) => self.put(key, value),
            None => self,
        }
    }

    fn int(self, key: &str, value: impl TryInto<i64>) -> Self {
        let value = value
            .try_into()
            .unwrap_or_else(|_| panic!("{key} does not fit a TOML integer"));
        self.put(key, value)
    }

    fn opt_int(self, key: &str, value: Option<impl TryInto<i64>>) -> Self {
        match value {
            Some(value) => self.int(key, value),
            None => self,
        }
    }

    fn table(self) -> Table {
        self.0
    }

    fn value(self) -> Value {
        Value::Table(self.0)
    }
}

fn strings(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn tables<T>(values: &[T], render: impl Fn(&T) -> Value) -> Value {
    Value::Array(values.iter().map(render).collect())
}

fn keyed<T>(values: &BTreeMap<String, T>, render: impl Fn(&T) -> Value) -> Value {
    Value::Table(
        values
            .iter()
            .map(|(key, value)| (key.clone(), render(value)))
            .collect(),
    )
}

/// The document of `config`.
pub(super) fn render_config(config: &BrokerConfig) -> Table {
    let BrokerConfig {
        deployment,
        network,
        execution_context,
        identity,
        credentials,
        imports,
        command_imports,
        oauth,
        managed_store,
        credential_encryption,
        management,
        broker_tokens,
        browser_auth,
        portal,
        mcp,
        policy,
        attribution,
        providers,
        gateways,
        limits,
        audit,
    } = config;
    Fields::default()
        .put("deployment", deployment_value(deployment))
        .put("network", network_value(network))
        .opt(
            "execution_context",
            execution_context.as_ref().map(execution_context_value),
        )
        .put("identity", identity_value(identity))
        .put("credentials", credentials_value(credentials))
        .put("imports", imports_value(imports))
        .put(
            "command_imports",
            keyed(command_imports, command_import_value),
        )
        .put("oauth", oauth_value(oauth))
        .opt(
            "managed_store",
            managed_store.as_ref().map(managed_store_value),
        )
        .opt(
            "credential_encryption",
            credential_encryption
                .as_ref()
                .map(credential_encryption_value),
        )
        .put("management", management_value(management))
        .opt(
            "broker_tokens",
            broker_tokens.as_ref().map(broker_tokens_value),
        )
        .put("browser_auth", browser_auth_value(browser_auth))
        .put("portal", portal_value(portal))
        .put("mcp", mcp_value(mcp))
        .put("policy", policy_value(policy))
        .put("attribution", attribution_value(attribution))
        .put("providers", providers_value(providers))
        .put("gateways", keyed(gateways, gateway_value))
        .put("limits", limits_value(limits))
        .opt("audit", audit.as_ref().map(audit_value))
        .table()
}

fn deployment_value(deployment: &DeploymentConfig) -> Value {
    let DeploymentConfig {
        environment,
        allow_production_anonymous,
        enable_fake_service,
        node_id,
    } = deployment;
    Fields::default()
        .put("environment", environment.as_str())
        .put("allow_production_anonymous", *allow_production_anonymous)
        .put("enable_fake_service", *enable_fake_service)
        .opt("node_id", node_id.clone())
        .value()
}

fn network_value(network: &NetworkConfig) -> Value {
    let NetworkConfig {
        trusted_proxies,
        egress_proxy,
        outbound_tls,
    } = network;
    let OutboundTlsConfig {
        trust,
        ca_certificate,
    } = outbound_tls;
    let trust = match trust {
        OutboundTlsTrustMode::System => "system",
        OutboundTlsTrustMode::Custom => "custom",
        OutboundTlsTrustMode::SystemPlusCustom => "system_plus_custom",
    };
    Fields::default()
        .put("trusted_proxies", strings(trusted_proxies))
        .opt(
            "egress_proxy",
            egress_proxy.as_ref().map(egress_proxy_value),
        )
        .put(
            "outbound_tls",
            Fields::default()
                .put("trust", trust)
                .opt(
                    "ca_certificate",
                    ca_certificate
                        .as_ref()
                        .map(|path| path.display().to_string()),
                )
                .value(),
        )
        .value()
}

fn egress_proxy_value(proxy: &EgressProxyConfig) -> Value {
    let EgressProxyConfig {
        url,
        username_ref,
        password_ref,
    } = proxy;
    Fields::default()
        .put("url", url.as_str())
        .opt("username_ref", username_ref.clone())
        .opt("password_ref", password_ref.clone())
        .value()
}

fn execution_context_value(context: &ExecutionContextConfig) -> Value {
    let ExecutionContextConfig {
        allowed_values,
        default_context,
    } = context;
    Fields::default()
        .put("allowed_values", strings(allowed_values))
        .opt("default_context", default_context.clone())
        .value()
}

fn identity_value(identity: &IdentityConfig) -> Value {
    let IdentityConfig {
        trusted_callers,
        mode,
        authority,
        sources,
        groups,
    } = identity;
    Fields::default()
        .put(
            "trusted_callers",
            keyed(trusted_callers, trusted_caller_value),
        )
        .put("mode", mode.as_str())
        .put("authority", authority.as_str())
        .put("sources", tables(sources, identity_source_value))
        .put("groups", tables(groups, identity_group_value))
        .value()
}

fn trusted_caller_value(caller: &TrustedCallerConfig) -> Value {
    let TrustedCallerConfig {
        credential_ref,
        credential_transport,
        username_namespace,
        context_mode,
        execution_context,
        allowed_execution_contexts,
        allow_forwarded_identity,
    } = caller;
    let context_mode = match context_mode {
        TrustedCallerContextMode::Fixed => "fixed",
        TrustedCallerContextMode::Asserted => "asserted",
    };
    Fields::default()
        .put("credential_ref", credential_ref.as_str())
        .put("credential_transport", credential_transport.as_str())
        .opt("username_namespace", username_namespace.clone())
        .put("context_mode", context_mode)
        .opt("execution_context", execution_context.clone())
        .opt(
            "allowed_execution_contexts",
            allowed_execution_contexts.as_deref().map(strings),
        )
        .put("allow_forwarded_identity", *allow_forwarded_identity)
        .value()
}

fn identity_source_value(source: &IdentitySourceConfig) -> Value {
    let IdentitySourceConfig {
        name,
        kind,
        header,
        scheme,
        principals,
    } = source;
    Fields::default()
        .put("name", name.as_str())
        .put("type", kind.as_str())
        .put("header", header.as_str())
        .put("scheme", scheme.as_str())
        .put("principals", tables(principals, static_principal_value))
        .value()
}

fn static_principal_value(principal: &StaticPrincipalConfig) -> Value {
    let StaticPrincipalConfig {
        principal,
        token_refs,
    } = principal;
    Fields::default()
        .put("principal", principal.as_str())
        .put("token_refs", strings(token_refs))
        .value()
}

fn identity_group_value(group: &IdentityGroupConfig) -> Value {
    let IdentityGroupConfig {
        id,
        status,
        members,
    } = group;
    Fields::default()
        .put("id", id.as_str())
        .put("status", status.as_str())
        .put("members", strings(members))
        .value()
}

fn credentials_value(credentials: &CredentialsConfig) -> Value {
    let CredentialsConfig {
        imported_modes,
        connections,
        service,
        per_user,
        lookup,
    } = credentials;
    assert!(
        imported_modes.is_empty(),
        "credentials.imported_modes come from the managed store, never TOML"
    );
    Fields::default()
        .put("connections", keyed(connections, connection_value))
        .put("service", keyed(service, credential_value))
        .put("per_user", keyed(per_user, credential_value))
        .put("lookup", keyed(lookup, credential_value))
        .value()
}

fn credential_value(credential: &CredentialConfig) -> Value {
    let CredentialConfig {
        kind,
        username_ref,
        token_ref,
        provider,
        path,
        read_only,
        connection,
        profile,
    } = credential;
    Fields::default()
        .put("type", kind.as_str())
        .opt("username_ref", username_ref.clone())
        .opt("token_ref", token_ref.clone())
        .opt("provider", provider.clone())
        .opt("path", path.clone())
        .opt("read_only", *read_only)
        .opt("connection", connection.clone())
        .opt("profile", profile.clone())
        .value()
}

fn connection_value(connection: &ConnectionConfig) -> Value {
    let ConnectionConfig {
        display_name,
        token_profiles,
        service_account_token_profiles,
        oauth,
    } = connection;
    Fields::default()
        .opt("display_name", display_name.clone())
        .opt("token_profiles", token_profiles.clone())
        .opt(
            "service_account_token_profiles",
            service_account_token_profiles.clone(),
        )
        .opt(
            "oauth",
            oauth.as_ref().map(|oauth| {
                let ConnectionOAuthConfig {
                    registration,
                    profile,
                } = oauth;
                Fields::default()
                    .put("registration", registration.as_str())
                    .put("profile", profile.as_str())
                    .value()
            }),
        )
        .value()
}

fn imports_value(imports: &ImportsConfig) -> Value {
    let ImportsConfig {
        enabled,
        allowed_kinds,
        allowed_endpoints,
        disabled_services,
    } = imports;
    Fields::default()
        .put("enabled", *enabled)
        .put("allowed_kinds", strings(allowed_kinds))
        .put("allowed_endpoints", strings(allowed_endpoints))
        .put("disabled_services", strings(disabled_services))
        .value()
}

fn command_import_value(command: &CommandImportConfig) -> Value {
    let CommandImportConfig {
        path,
        timeout,
        max_output_bytes,
        max_concurrent,
        working_dir,
        network,
        log_stderr,
        env,
    } = command;
    Fields::default()
        .put("path", path.as_str())
        .put("timeout", timeout.as_str())
        .int("max_output_bytes", *max_output_bytes)
        .int("max_concurrent", *max_concurrent)
        .put("working_dir", working_dir.as_str())
        .put("network", network.as_str())
        .put("log_stderr", *log_stderr)
        .put("env", keyed(env, |value| Value::String(value.clone())))
        .value()
}

fn oauth_value(oauth: &OAuthConfig) -> Value {
    Value::try_from(oauth).expect("OAuth configuration renders")
}

fn managed_store_value(store: &ManagedStoreConfig) -> Value {
    let ManagedStoreConfig {
        kind,
        path,
        require_registered_principal_for_invocation,
        auto_migrate,
    } = store;
    Fields::default()
        .put("type", kind.as_str())
        .put("path", path.as_str())
        .put(
            "require_registered_principal_for_invocation",
            *require_registered_principal_for_invocation,
        )
        .put("auto_migrate", *auto_migrate)
        .value()
}

fn credential_encryption_value(encryption: &CredentialEncryptionConfig) -> Value {
    let CredentialEncryptionConfig { active_key, keys } = encryption;
    Fields::default()
        .put("active_key", active_key.as_str())
        .put(
            "keys",
            tables(keys, |key| {
                let CredentialEncryptionKeyConfig {
                    id,
                    provider,
                    env,
                    path,
                } = key;
                Fields::default()
                    .put("id", id.as_str())
                    .put("provider", provider.as_str())
                    .opt("env", env.clone())
                    .opt("path", path.clone())
                    .value()
            }),
        )
        .value()
}

fn management_value(management: &ManagementConfig) -> Value {
    let ManagementConfig {
        enabled,
        admin_principals,
        admin_groups,
        allow_classless_admin_identities,
        allow_classless_user_management,
        initial_admin,
    } = management;
    let InitialAdminConfig {
        mode,
        principal_id,
        initial_password,
    } = initial_admin;
    Fields::default()
        .put("enabled", *enabled)
        .put("admin_principals", strings(admin_principals))
        .put("admin_groups", strings(admin_groups))
        .put(
            "allow_classless_admin_identities",
            *allow_classless_admin_identities,
        )
        .put(
            "allow_classless_user_management",
            *allow_classless_user_management,
        )
        .put(
            "initial_admin",
            Fields::default()
                .put("mode", mode.as_str())
                .opt("principal_id", principal_id.clone())
                .opt("initial_password", initial_password.clone())
                .value(),
        )
        .value()
}

fn ttl_options(options: &[BrokerTokenTtlOption]) -> Value {
    Value::Array(
        options
            .iter()
            .map(|option| Value::String(option.as_str().to_string()))
            .collect(),
    )
}

fn broker_tokens_value(tokens: &BrokerTokensConfig) -> Value {
    let BrokerTokensConfig {
        hash_key_ref,
        default_agent_invoke_ttl,
        default_user_manage_ttl,
        default_admin_ttl,
        max_self_issued_agent_invoke_ttl,
        self_agent_invoke_ttl_options,
        admin_agent_invoke_ttl_options,
        user_manage_ttl_options,
        admin_ttl_options,
    } = tokens;
    Fields::default()
        .put("hash_key_ref", hash_key_ref.as_str())
        .opt("default_agent_invoke_ttl", default_agent_invoke_ttl.clone())
        .opt("default_user_manage_ttl", default_user_manage_ttl.clone())
        .opt("default_admin_ttl", default_admin_ttl.clone())
        .opt(
            "max_self_issued_agent_invoke_ttl",
            max_self_issued_agent_invoke_ttl.clone(),
        )
        .put(
            "self_agent_invoke_ttl_options",
            ttl_options(self_agent_invoke_ttl_options),
        )
        .put(
            "admin_agent_invoke_ttl_options",
            ttl_options(admin_agent_invoke_ttl_options),
        )
        .put(
            "user_manage_ttl_options",
            ttl_options(user_manage_ttl_options),
        )
        .put("admin_ttl_options", ttl_options(admin_ttl_options))
        .value()
}

fn browser_auth_value(browser: &BrowserAuthConfig) -> Value {
    let BrowserAuthConfig {
        enabled,
        public_origin,
        session_cookie_name,
        csrf_header,
        csrf_key_ref,
        session_ttl,
        allowed_return_paths,
        local_password,
        oidc,
    } = browser;
    let LocalPasswordConfig {
        enabled: password_enabled,
        pepper_ref,
        min_password_length,
        max_failed_attempts,
        lockout_ttl,
    } = local_password;
    let OidcConfig { microsoft } = oidc;
    let MicrosoftOidcConfig {
        enabled: microsoft_enabled,
        tenant_id,
        client_id,
        client_secret_ref,
        flow_key_ref,
        flow_ttl,
        max_pending_flows,
        jit_provisioning,
        external_membership_ttl,
        membership_renewal,
    } = microsoft;
    Fields::default()
        .put("enabled", *enabled)
        .opt("public_origin", public_origin.clone())
        .put("session_cookie_name", session_cookie_name.as_str())
        .put("csrf_header", csrf_header.as_str())
        .opt("csrf_key_ref", csrf_key_ref.clone())
        .put("session_ttl", session_ttl.as_str())
        .put("allowed_return_paths", strings(allowed_return_paths))
        .put(
            "local_password",
            Fields::default()
                .put("enabled", *password_enabled)
                .opt("pepper_ref", pepper_ref.clone())
                .int("min_password_length", *min_password_length)
                .int("max_failed_attempts", *max_failed_attempts)
                .put("lockout_ttl", lockout_ttl.as_str())
                .value(),
        )
        .put(
            "oidc",
            Fields::default()
                .put(
                    "microsoft",
                    Fields::default()
                        .put("enabled", *microsoft_enabled)
                        .opt("tenant_id", tenant_id.clone())
                        .opt("client_id", client_id.clone())
                        .opt("client_secret_ref", client_secret_ref.clone())
                        .opt("flow_key_ref", flow_key_ref.clone())
                        .put("flow_ttl", flow_ttl.as_str())
                        .int("max_pending_flows", *max_pending_flows)
                        .put("jit_provisioning", *jit_provisioning)
                        .put("external_membership_ttl", external_membership_ttl.as_str())
                        .put("membership_renewal", *membership_renewal)
                        .value(),
                )
                .value(),
        )
        .value()
}

fn portal_value(portal: &PortalConfig) -> Value {
    let PortalConfig {
        enabled,
        mount_path,
        static_dir,
    } = portal;
    Fields::default()
        .put("enabled", *enabled)
        .put("mount_path", mount_path.as_str())
        .opt("static_dir", static_dir.clone())
        .value()
}

fn mcp_value(mcp: &McpConfig) -> Value {
    let McpConfig {
        enabled,
        public_url,
        allowed_origins,
        max_request_bytes,
        max_response_bytes,
        max_catalog_bytes,
        operation_timeout_ms,
        protocol_timeout_ms,
        max_sessions,
        max_sessions_per_principal,
        session_idle_timeout_ms,
        session_max_lifetime_ms,
        max_control_requests,
        max_control_requests_per_principal,
    } = mcp;
    Fields::default()
        .put("enabled", *enabled)
        .opt("public_url", public_url.clone())
        .put("allowed_origins", strings(allowed_origins))
        .int("max_request_bytes", *max_request_bytes)
        .int("max_response_bytes", *max_response_bytes)
        .int("max_catalog_bytes", *max_catalog_bytes)
        .int("operation_timeout_ms", *operation_timeout_ms)
        .int("protocol_timeout_ms", *protocol_timeout_ms)
        .int("max_sessions", *max_sessions)
        .int("max_sessions_per_principal", *max_sessions_per_principal)
        .int("session_idle_timeout_ms", *session_idle_timeout_ms)
        .int("session_max_lifetime_ms", *session_max_lifetime_ms)
        .int("max_control_requests", *max_control_requests)
        .int(
            "max_control_requests_per_principal",
            *max_control_requests_per_principal,
        )
        .value()
}

fn policy_value(policy: &PolicyConfig) -> Value {
    let PolicyConfig {
        authority,
        default_decision,
        grants,
        resources,
        resource_groups,
    } = policy;
    Fields::default()
        .put("authority", authority.as_str())
        .put("default_decision", default_decision.as_str())
        .put("grants", tables(grants, grant_value))
        .put("resources", tables(resources, resource_value))
        .put(
            "resource_groups",
            tables(resource_groups, resource_group_value),
        )
        .value()
}

pub(super) fn grant_value(grant: &PolicyGrantConfig) -> Value {
    let PolicyGrantConfig {
        subjects,
        service,
        actions,
        resources,
        execution_contexts,
        credential_mode,
        priority,
    } = grant;
    Fields::default()
        .put("subjects", strings(subjects))
        .put("service", service.as_str())
        .put("actions", strings(actions))
        .put("resources", selection_value(resources))
        .opt(
            "execution_contexts",
            execution_contexts.as_deref().map(strings),
        )
        .put("credential_mode", credential_mode.as_str())
        .opt_int("priority", *priority)
        .value()
}

pub(super) fn selection_value(selection: &ResourceSelection) -> Value {
    let ResourceSelection {
        resource_ids,
        resource_group_ids,
    } = selection;
    Fields::default()
        .put("resource_ids", strings(resource_ids))
        .put("resource_group_ids", strings(resource_group_ids))
        .value()
}

pub(super) fn resource_value(resource: &ResourceDefinition) -> Value {
    let ResourceDefinition {
        id,
        display_name,
        resource_type,
        selector,
        allowed_execution_contexts,
        enabled,
    } = resource;
    Fields::default()
        .put("id", id.as_str())
        .opt("display_name", display_name.clone())
        .put("resource_type", resource_type.as_str())
        .put(
            "selector",
            Value::try_from(selector).expect("selectors render"),
        )
        .put(
            "allowed_execution_contexts",
            strings(allowed_execution_contexts),
        )
        .put("enabled", *enabled)
        .value()
}

fn resource_group_value(group: &ResourceGroupDefinition) -> Value {
    let ResourceGroupDefinition {
        id,
        name,
        included_resource_ids,
        excluded_resource_ids,
    } = group;
    Fields::default()
        .put("id", id.as_str())
        .put("name", name.as_str())
        .put("included_resource_ids", strings(included_resource_ids))
        .put("excluded_resource_ids", strings(excluded_resource_ids))
        .value()
}

fn attribution_value(attribution: &AttributionConfig) -> Value {
    let AttributionConfig { actions } = attribution;
    Fields::default()
        .put("actions", keyed(actions, |patterns| strings(patterns)))
        .value()
}

fn gateway_value(gateway: &GatewayConfig) -> Value {
    let GatewayConfig {
        allow_forwarded_identity,
        kind,
        display_name,
        broker_hosts,
        upstream_base_url,
        allowed_upstream_hosts,
        egress_proxy,
        auth_modes,
        basic_broker_token_username,
        credential_modes,
        upstream_token_auth,
        redirect_policy,
        request_body_max_bytes,
        response_body_max_bytes,
        streaming_idle_timeout_ms,
        correlation_headers,
        git,
    } = gateway;
    Fields::default()
        .put("allow_forwarded_identity", *allow_forwarded_identity)
        .put("kind", kind.as_str())
        .put("display_name", display_name.as_str())
        .put("broker_hosts", strings(broker_hosts))
        .put("upstream_base_url", upstream_base_url.as_str())
        .put("allowed_upstream_hosts", strings(allowed_upstream_hosts))
        .opt(
            "egress_proxy",
            egress_proxy.as_ref().map(egress_proxy_value),
        )
        .put("auth_modes", strings(auth_modes))
        .put(
            "basic_broker_token_username",
            basic_broker_token_username.as_str(),
        )
        .put("credential_modes", strings(credential_modes))
        .put(
            "upstream_token_auth",
            match upstream_token_auth {
                GatewayUpstreamTokenAuth::Bearer {} => Fields::default().put("scheme", "bearer"),
                GatewayUpstreamTokenAuth::Basic { username } => Fields::default()
                    .put("scheme", "basic")
                    .put("username", username.as_str()),
            }
            .value(),
        )
        .put("redirect_policy", redirect_policy.as_str())
        .opt_int("request_body_max_bytes", *request_body_max_bytes)
        .opt_int("response_body_max_bytes", *response_body_max_bytes)
        .opt_int("streaming_idle_timeout_ms", *streaming_idle_timeout_ms)
        .put("correlation_headers", *correlation_headers)
        .opt(
            "git",
            git.as_ref().map(|git| {
                let GatewayGitConfig {
                    allow_fetch,
                    allow_push,
                    deny_ref_patterns,
                    deny_delete_refs,
                    receive_pack_prefix_max_bytes,
                } = git;
                Fields::default()
                    .put("allow_fetch", *allow_fetch)
                    .put("allow_push", *allow_push)
                    .put("deny_ref_patterns", strings(deny_ref_patterns))
                    .put("deny_delete_refs", *deny_delete_refs)
                    .opt_int(
                        "receive_pack_prefix_max_bytes",
                        *receive_pack_prefix_max_bytes,
                    )
                    .value()
            }),
        )
        .value()
}

fn limits_value(limits: &LimitsConfig) -> Value {
    let LimitsConfig {
        invocations,
        auth_requests_per_principal_per_minute,
        auth_requests_per_source_per_minute,
        max_concurrent_requests,
        max_concurrent_requests_per_principal,
        max_http_body_bytes,
        max_download_bytes,
        max_upstream_response_bytes,
        request_timeout_ms,
        request_body_timeout_ms,
        streaming_idle_timeout_ms,
        upload_spool_dir,
        upload_spool_max_bytes,
    } = limits;
    let InvocationLimitsConfig {
        default,
        services,
        principal_overrides,
    } = invocations;
    let limit = |limit: &InvocationLimitConfig| {
        let InvocationLimitConfig { requests, window } = limit;
        Fields::default()
            .int("requests", *requests)
            .put("window", window.as_str())
            .value()
    };
    Fields::default()
        .put(
            "invocations",
            Fields::default()
                .opt("default", default.as_ref().map(limit))
                .put("services", keyed(services, limit))
                .put(
                    "principal_overrides",
                    tables(principal_overrides, |entry| {
                        let PrincipalInvocationLimitConfig {
                            principal,
                            service,
                            requests,
                            window,
                        } = entry;
                        Fields::default()
                            .put("principal", principal.as_str())
                            .put("service", service.as_str())
                            .int("requests", *requests)
                            .put("window", window.as_str())
                            .value()
                    }),
                )
                .value(),
        )
        .int(
            "auth_requests_per_principal_per_minute",
            *auth_requests_per_principal_per_minute,
        )
        .int(
            "auth_requests_per_source_per_minute",
            *auth_requests_per_source_per_minute,
        )
        .int("max_concurrent_requests", *max_concurrent_requests)
        .int(
            "max_concurrent_requests_per_principal",
            *max_concurrent_requests_per_principal,
        )
        .int("max_http_body_bytes", *max_http_body_bytes)
        .int("max_download_bytes", *max_download_bytes)
        .int("max_upstream_response_bytes", *max_upstream_response_bytes)
        .int("request_timeout_ms", *request_timeout_ms)
        .int("request_body_timeout_ms", *request_body_timeout_ms)
        .int("streaming_idle_timeout_ms", *streaming_idle_timeout_ms)
        .put("upload_spool_dir", upload_spool_dir.as_str())
        .int("upload_spool_max_bytes", *upload_spool_max_bytes)
        .value()
}

fn audit_value(audit: &AuditConfig) -> Value {
    let AuditConfig {
        kind,
        path,
        rotate_bytes,
        retention_days,
        queue_capacity,
        terminal_queue_capacity,
        enqueue_timeout_ms,
        durability,
    } = audit;
    let durability = match durability {
        AuditDurability::Write => "write",
        AuditDurability::SyncData => "sync_data",
        AuditDurability::SyncAll => "sync_all",
    };
    Fields::default()
        .put("type", kind.as_str())
        .put("path", path.as_str())
        .opt_int("rotate_bytes", *rotate_bytes)
        .int("retention_days", *retention_days)
        .int("queue_capacity", *queue_capacity)
        .opt_int("terminal_queue_capacity", *terminal_queue_capacity)
        .int("enqueue_timeout_ms", *enqueue_timeout_ms)
        .put("durability", durability)
        .value()
}

fn providers_value(providers: &ProvidersConfig) -> Value {
    let mut table = Table::new();
    for backend in providers.iter() {
        let kind = backend.kind();
        let value = match kind {
            "fake" => match providers.get::<super::mcp::names::NamingBackend>() {
                Some(naming) => {
                    let super::mcp::names::NamingBackend { collision } = naming;
                    Fields::default().put("collision", *collision).value()
                }
                None => {
                    let FakeProviderConfig {} = providers.get::<FakeProviderConfig>().unwrap();
                    Value::Table(Table::new())
                }
            },
            "gmail" => {
                let GmailConfig {} = providers.get::<GmailConfig>().unwrap();
                Value::Table(Table::new())
            }
            "jira" => jira_value(providers.get().unwrap()),
            "confluence" => confluence_value(providers.get().unwrap()),
            "gitlab" => gitlab_value(providers.get().unwrap()),
            "cloudbees_ci" => cloudbees_value(providers.get().unwrap()),
            "teams" => teams_value(providers.get().unwrap()),
            "oauth_stub" => {
                match providers.get::<super::oauth::atlassian_dialect::AtlassianSiteConsumer>() {
                    Some(consumer) => {
                        let super::oauth::atlassian_dialect::AtlassianSiteConsumer { cloud_id } =
                            consumer;
                        Fields::default().put("cloud_id", cloud_id.as_str()).value()
                    }
                    None => {
                        let OAuthStubProviderConfig { base_url } = providers.get().unwrap();
                        Fields::default().put("base_url", base_url.as_str()).value()
                    }
                }
            }
            "conformance" => conformance_value(providers.get().unwrap()),
            "verifier" => {
                let super::domain_reasons::VerifierConfig {} = providers.get().unwrap();
                Value::Table(Table::new())
            }
            other => panic!("render [providers.{other}] for host tests"),
        };
        table.insert(kind.to_string(), value);
    }
    Value::Table(table)
}

fn attachments_value(attachments: &AttachmentLimitsConfig) -> Value {
    let AttachmentLimitsConfig {
        max_bytes,
        max_total_bytes,
        max_download_bytes,
        media_types,
    } = attachments;
    Fields::default()
        .int("max_bytes", *max_bytes)
        .int("max_total_bytes", *max_total_bytes)
        .int("max_download_bytes", *max_download_bytes)
        .put("media_types", strings(media_types))
        .value()
}

fn search_value(search: &SearchLimitsConfig) -> Value {
    let SearchLimitsConfig { max_results } = search;
    Fields::default().int("max_results", *max_results).value()
}

fn jira_value(jira: &JiraProviderConfig) -> Value {
    let JiraProviderConfig {
        tenant_host,
        cloud_id,
        egress_proxy,
        allowed_upstream_hosts,
        attachments,
        content,
        search,
        listing,
        comments,
        issue_links,
    } = jira;
    let JiraContentConfig {
        comment_formats,
        max_body_bytes,
    } = content;
    let JiraCommentsConfig {
        max_results,
        max_property_value_bytes,
        allowed_property_key_prefixes,
        allowed_visibility,
    } = comments;
    let JiraIssueLinksConfig {
        dependency_link_type,
        dependency_outward,
        dependency_inward,
    } = issue_links;
    Fields::default()
        .put("tenant_host", tenant_host.as_str())
        .opt("cloud_id", cloud_id.clone())
        .opt(
            "egress_proxy",
            egress_proxy.as_ref().map(egress_proxy_value),
        )
        .put("allowed_upstream_hosts", strings(allowed_upstream_hosts))
        .put("attachments", attachments_value(attachments))
        .put(
            "content",
            Fields::default()
                .put("comment_formats", strings(comment_formats))
                .int("max_body_bytes", *max_body_bytes)
                .value(),
        )
        .put(
            "listing",
            Fields::default()
                .int("max_results", listing.max_results)
                .int("max_candidate_pages", listing.max_candidate_pages)
                .int("max_upstream_requests", listing.max_upstream_requests)
                .int("max_scan_bytes", listing.max_scan_bytes)
                .value(),
        )
        .put("search", search_value(search))
        .put(
            "comments",
            Fields::default()
                .int("max_results", *max_results)
                .int("max_property_value_bytes", *max_property_value_bytes)
                .put(
                    "allowed_property_key_prefixes",
                    strings(allowed_property_key_prefixes),
                )
                .put(
                    "allowed_visibility",
                    tables(allowed_visibility, |visibility| {
                        let JiraCommentVisibilityConfig {
                            visibility_type,
                            value,
                            identifier,
                        } = visibility;
                        Fields::default()
                            .put("type", visibility_type.as_str())
                            .opt("value", value.clone())
                            .opt("identifier", identifier.clone())
                            .value()
                    }),
                )
                .value(),
        )
        .put(
            "issue_links",
            Fields::default()
                .put("dependency_link_type", dependency_link_type.as_str())
                .put("dependency_outward", dependency_outward.as_str())
                .put("dependency_inward", dependency_inward.as_str())
                .value(),
        )
        .value()
}

fn confluence_value(confluence: &ConfluenceProviderConfig) -> Value {
    let ConfluenceProviderConfig {
        listing,
        tenant_host,
        cloud_id,
        egress_proxy,
        allowed_upstream_hosts,
        attachments,
        content,
        search,
    } = confluence;
    let ConfluenceContentConfig {
        page_formats,
        blog_formats,
        comment_formats,
        max_body_bytes,
    } = content;
    Fields::default()
        .put("tenant_host", tenant_host.as_str())
        .opt("cloud_id", cloud_id.clone())
        .opt(
            "egress_proxy",
            egress_proxy.as_ref().map(egress_proxy_value),
        )
        .put("allowed_upstream_hosts", strings(allowed_upstream_hosts))
        .put("attachments", attachments_value(attachments))
        .put(
            "content",
            Fields::default()
                .put("page_formats", strings(page_formats))
                .put("blog_formats", strings(blog_formats))
                .put("comment_formats", strings(comment_formats))
                .int("max_body_bytes", *max_body_bytes)
                .value(),
        )
        .put(
            "listing",
            Fields::default()
                .int("max_results", listing.max_results)
                .int("max_candidate_pages", listing.max_candidate_pages)
                .int("max_upstream_requests", listing.max_upstream_requests)
                .int("max_scan_bytes", listing.max_scan_bytes)
                .value(),
        )
        .put("search", search_value(search))
        .value()
}

fn gitlab_search_value(search: &GitlabSearchConfig) -> Value {
    let GitlabSearchConfig {
        max_results,
        default_engine,
        max_candidate_pages,
        max_upstream_requests,
        max_scan_bytes,
        engines,
    } = search;
    let GitlabSearchEnginesConfig {
        basic,
        advanced,
        zoekt,
    } = engines;
    Fields::default()
        .int("max_results", *max_results)
        .put("default_engine", default_engine.as_str())
        .int("max_candidate_pages", *max_candidate_pages)
        .int("max_upstream_requests", *max_upstream_requests)
        .int("max_scan_bytes", *max_scan_bytes)
        .put(
            "engines",
            Fields::default()
                .put("basic", gitlab_search_engine_value(basic))
                .put("advanced", gitlab_search_engine_value(advanced))
                .put("zoekt", gitlab_search_engine_value(zoekt))
                .value(),
        )
        .value()
}

fn gitlab_search_engine_value(engine: &GitlabSearchEngineConfig) -> Value {
    let GitlabSearchEngineConfig {
        project_categories,
        instance_categories,
    } = engine;
    Fields::default()
        .put("project_categories", strings(project_categories))
        .put("instance_categories", strings(instance_categories))
        .value()
}

fn gitlab_value(gitlab: &GitlabProviderConfig) -> Value {
    let GitlabProviderConfig {
        provisioning,
        attachments,
        api_base_url,
        web_base_url,
        egress_proxy,
        allowed_upstream_hosts,
        webhooks,
        content,
        search,
    } = gitlab;
    let GitlabProvisioningConfig {
        enabled,
        max_access_level,
        max_token_lifetime_days,
        allowed_token_scopes,
    } = provisioning;
    let GitlabUploadLimitsConfig {
        max_bytes,
        max_total_bytes,
        media_types,
    } = attachments;
    let GitlabWebhooksConfig {
        allowed_destinations,
        allow_disable_ssl_verification,
    } = webhooks;
    let GitlabContentConfig {
        max_body_bytes,
        max_commit_actions,
        max_file_bytes,
        max_raw_download_bytes,
    } = content;
    Fields::default()
        .put(
            "provisioning",
            Fields::default()
                .put("enabled", *enabled)
                .int("max_access_level", *max_access_level)
                .int("max_token_lifetime_days", *max_token_lifetime_days)
                .put("allowed_token_scopes", strings(allowed_token_scopes))
                .value(),
        )
        .put(
            "attachments",
            Fields::default()
                .int("max_bytes", *max_bytes)
                .int("max_total_bytes", *max_total_bytes)
                .put("media_types", strings(media_types))
                .value(),
        )
        .put("api_base_url", api_base_url.as_str())
        .put("web_base_url", web_base_url.as_str())
        .opt(
            "egress_proxy",
            egress_proxy.as_ref().map(egress_proxy_value),
        )
        .put("allowed_upstream_hosts", strings(allowed_upstream_hosts))
        .put(
            "webhooks",
            Fields::default()
                .put("allowed_destinations", strings(allowed_destinations))
                .put(
                    "allow_disable_ssl_verification",
                    *allow_disable_ssl_verification,
                )
                .value(),
        )
        .put(
            "content",
            Fields::default()
                .int("max_body_bytes", *max_body_bytes)
                .int("max_commit_actions", *max_commit_actions)
                .int("max_file_bytes", *max_file_bytes)
                .int("max_raw_download_bytes", *max_raw_download_bytes)
                .value(),
        )
        .put("search", gitlab_search_value(search))
        .value()
}

fn cloudbees_value(cloudbees: &CloudbeesCiProviderConfig) -> Value {
    let CloudbeesCiProviderConfig {
        listing,
        max_log_scan_bytes,
        controllers,
        egress_proxy,
        allowed_upstream_hosts,
    } = cloudbees;
    Fields::default()
        .put(
            "listing",
            Fields::default()
                .int("max_results", listing.max_results)
                .int("max_candidate_pages", listing.max_candidate_pages)
                .int("max_upstream_requests", listing.max_upstream_requests)
                .int("max_scan_bytes", listing.max_scan_bytes)
                .value(),
        )
        .int("max_log_scan_bytes", *max_log_scan_bytes)
        .put(
            "controllers",
            keyed(controllers, |controller| {
                let CloudbeesCiControllerConfig {
                    base_url,
                    web_base_url,
                } = controller;
                Fields::default()
                    .put("base_url", base_url.as_str())
                    .opt("web_base_url", web_base_url.clone())
                    .value()
            }),
        )
        .opt(
            "egress_proxy",
            egress_proxy.as_ref().map(egress_proxy_value),
        )
        .put("allowed_upstream_hosts", strings(allowed_upstream_hosts))
        .value()
}

fn teams_value(teams: &TeamsConfig) -> Value {
    let TeamsConfig {
        allowed_upstream_hosts,
        egress_proxy,
    } = teams;
    Fields::default()
        .put("allowed_upstream_hosts", strings(allowed_upstream_hosts))
        .opt(
            "egress_proxy",
            egress_proxy.as_ref().map(egress_proxy_value),
        )
        .value()
}

fn conformance_value(conformance: &ConformanceConfig) -> Value {
    let ConformanceConfig {
        base_url,
        allowed_upstream_hosts,
        egress_proxy,
        max_upload_bytes,
        endpoints,
        shelves,
    } = conformance;
    Fields::default()
        .put("base_url", base_url.as_str())
        .put("allowed_upstream_hosts", strings(allowed_upstream_hosts))
        .opt(
            "egress_proxy",
            egress_proxy.as_ref().map(egress_proxy_value),
        )
        .int("max_upload_bytes", *max_upload_bytes)
        .put("endpoints", *endpoints)
        .put("shelves", strings(shelves))
        .value()
}
