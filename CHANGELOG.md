# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Breaking Changes

- OAuth loopback exceptions now require a literal IPv4/IPv6 loopback address.
  `http://localhost` is rejected for MCP OAuth endpoints and OAuth destinations;
  use `http://127.0.0.1` or `http://[::1]` with `allow_insecure_loopback = true`.
  `https://localhost` and every other host name now follow the global egress
  proxy resolution instead of connecting directly. Each approved OAuth
  destination origin is routed independently.
- The provider SDK (`agent-access-provider`) no longer exports host network
  plumbing. `PreparedOutboundTls`, `OutboundTlsConfig`, `OutboundTlsTrustMode`,
  `parse_strict_certificate_pem_bundle`, `EgressProxyEnvironment`,
  `EgressProxyRuntimeConfig`, `EgressProxySelection`, `EgressProxyMode`,
  `apply_reqwest_proxy`, `preflight_egress_proxy`, `load_secret_ref_value`,
  `ConfigError` and `UpstreamNetwork` are removed; the TLS, configuration-error
  and secret-reference items now live in `agent-access-core`. Backends build
  clients with `UpstreamClient::build(spec, host.clients())`, where the new
  `host` module's `UpstreamClientFactory` is implemented by the Broker host,
  `UpstreamClientSpec::egress` takes an `EgressDeclaration`, and
  `UpstreamClient::egress_route` returns a sanitized `EgressRoute`.
  `BuildContext` has private fields with accessors and is constructed by
  `host::build_context`; provider tests use `test_support::TestHost`, which
  replaces `test_support::test_outbound_tls`.
- `HostError` is replaced by `ProviderBuildError` in `BackendConfig::build`,
  `ImportedAdapter::build` and `OAuthHttp::build`. It carries safe
  configuration diagnostics; host network failures keep their cause for the
  Broker's own diagnostics.

### Added

- Release qualification runs a required `crate-boundaries` gate
  (`node scripts/check-crate-boundaries.mjs`). Every workspace crate declares a
  role, and the check rejects dependencies that cross the role boundaries.

### Changed

- Broker process lifecycle, HTTP, MCP, management, gateway, and reload events
  now log under `agent_access_broker_host::…` targets instead of
  `agent_access_broker` and `agent_access_broker::…`; lifecycle events such as
  `broker_starting`, `broker_listening`, and `broker_shutdown` use
  `agent_access_broker_host::lifecycle`. Update module-level `RUST_LOG`
  directives accordingly. The default filter now names
  `agent_access_broker_host=info` explicitly, which the `fallback` field of
  `logging_filter_invalid` reports. The `agent_access_broker::handlers::oidc`
  diagnostic target is unchanged.
- `agent-access-broker serve`, and the broker run without a subcommand, now exit
  `3` instead of `1` when the configuration cannot be read, parsed, or
  validated at startup, matching `config validate`. Other startup and runtime
  failures still exit `1`, and the `Error: …` message is unchanged.

### Fixed

### Removed

## [0.1.0] - 2026-10-11

### Initial release

- A standalone Broker and CLI for scoped, audited access to service APIs while
  keeping upstream credentials in the Broker.
- Managed accounts, groups, typed resources, execution contexts, service policies,
  grants, restricted agent tokens, and trusted human identity through configured
  ingress callers.
- A same-origin portal for administration, personal credentials and OAuth,
  access management, and audit investigation.
- Typed CLI commands, native HTTP and local stdio MCP, catalog-driven invocation,
  runtime schemas, and a governed Git smart HTTP gateway.
- Integrations for Jira, Confluence, GitLab, CloudBees CI, Gmail, Teams Workflows,
  imported HTTP MCP services, and imported OpenAPI services.
- Encrypted credential storage, delegated OAuth, key rotation, bounded transfers,
  outbound destination controls, quotas, and structured audit and observability.
- Operator and administrator guides, sample configurations, dependency notices,
  and a release workflow that qualifies the exact commit before publication.
