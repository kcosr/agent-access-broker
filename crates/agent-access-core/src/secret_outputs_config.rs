use serde::{Deserialize, Serialize};

/// How the Broker delivers explicitly declared, transferable provider secrets.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretOutputMode {
    #[default]
    Reference,
    Raw,
}

/// Operator-owned temporary secret storage and delivery policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretOutputsConfig {
    pub mode: SecretOutputMode,
    pub ttl_seconds: u64,
    pub max_refs_per_principal: u64,
    pub max_refs_total: u64,
    pub max_bytes_per_principal: u64,
    pub max_bytes_total: u64,
    pub receipt_retention_seconds: u64,
    pub max_receipts_total: u64,
}

impl Default for SecretOutputsConfig {
    fn default() -> Self {
        Self {
            mode: SecretOutputMode::Reference,
            ttl_seconds: 14_400,
            max_refs_per_principal: 100,
            max_refs_total: 10_000,
            max_bytes_per_principal: 1_048_576,
            max_bytes_total: 67_108_864,
            receipt_retention_seconds: 604_800,
            max_receipts_total: 100_000,
        }
    }
}

pub(crate) fn validate(config: &crate::BrokerConfig, errors: &mut Vec<String>) {
    let policy = &config.secret_outputs;
    if !(1..=86_400).contains(&policy.ttl_seconds) {
        errors.push("secret_outputs.ttl_seconds must be between 1 and 86400".into());
    }
    // Reservation precedes dispatch. Reject lifetimes that an ordinary request
    // or MCP operation can consume before its one-time output is captured.
    if policy.mode == SecretOutputMode::Reference
        && policy.ttl_seconds.saturating_mul(1000)
            <= config
                .limits
                .request_timeout_ms
                .max(config.mcp.operation_timeout_ms)
    {
        errors.push("secret_outputs.ttl_seconds must exceed both limits.request_timeout_ms and mcp.operation_timeout_ms (converted to seconds) in reference mode".into());
    }
    if !(1..=2_592_000).contains(&policy.receipt_retention_seconds) {
        errors
            .push("secret_outputs.receipt_retention_seconds must be between 1 and 2592000".into());
    }
    if policy.max_refs_per_principal == 0
        || policy.max_refs_per_principal > policy.max_refs_total
        || policy.max_refs_total > 1_000_000
        || policy.max_bytes_per_principal == 0
        || policy.max_bytes_per_principal > policy.max_bytes_total
        || policy.max_bytes_total > 1_073_741_824
        || policy.max_receipts_total < policy.max_refs_total
        || policy.max_receipts_total > 10_000_000
    {
        errors.push("secret_outputs quotas must be positive, per-principal quotas must not exceed totals, total references must not exceed 1000000, total bytes must not exceed 1073741824, and receipt capacity must cover references without exceeding 10000000".into());
    }
    let needs_store = crate::configured_service_descriptors(config)
        .values()
        .flat_map(|service| &service.actions)
        .any(|action| {
            !action.secret_inputs.is_empty()
                || (policy.mode == SecretOutputMode::Reference && !action.secret_outputs.is_empty())
        });
    if needs_store && (config.managed_store.is_none() || config.credential_encryption.is_none()) {
        errors.push("reference-capable actions require managed_store and credential_encryption; explicitly set secret_outputs.mode = 'raw' for secret-output-only deployments without temporary storage".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_fixed_and_raw_requires_an_explicit_choice() {
        let defaults: SecretOutputsConfig = toml::from_str("").unwrap();
        assert_eq!(defaults.mode, SecretOutputMode::Reference);
        assert_eq!(defaults.ttl_seconds, 14_400);
        let raw: SecretOutputsConfig = toml::from_str("mode = 'raw'").unwrap();
        assert_eq!(raw.mode, SecretOutputMode::Raw);
        assert!(toml::from_str::<SecretOutputsConfig>("mode = 'plaintext'").is_err());
        assert!(toml::from_str::<SecretOutputsConfig>("sliding = true").is_err());
    }

    #[test]
    fn reference_lifetime_must_outlast_request_and_operation_budgets() {
        let mut config = crate::tests::parse_test_config(
            r#"
[identity]
mode = "optional"
authority = "toml"
[policy]
authority = "toml"
[limits]
upload_spool_dir = "upload-spool"
request_timeout_ms = 30000
[mcp]
operation_timeout_ms = 120000
"#,
        )
        .unwrap();
        for (ttl, valid) in [(1, false), (120, false), (121, true)] {
            config.secret_outputs.ttl_seconds = ttl;
            let mut errors = Vec::new();
            validate(&config, &mut errors);
            assert_eq!(errors.is_empty(), valid, "{ttl}: {errors:?}");
        }
        config.limits.request_timeout_ms = 180000;
        let mut errors = Vec::new();
        validate(&config, &mut errors);
        assert!(!errors.is_empty());
        config.secret_outputs.mode = SecretOutputMode::Raw;
        errors.clear();
        validate(&config, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
    }
}
