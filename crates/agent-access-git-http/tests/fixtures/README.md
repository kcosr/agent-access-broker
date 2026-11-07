# Git policy baseline

`git-config-descriptor-baseline.json` records nine combinations of fetch/push
permissions and service/personal credential modes. Its TOML inputs cover the
public defaults and an explicit common/Git configuration.

The expected values were captured by executing the original `GatewayConfig`,
`GatewayGitConfig`, and `gateway_service_descriptor` definitions from Broker
commit `1bbaa55822025dfc96e683785d93f5ba224d95d3`. The fixture records the
configuration and factory source hashes. The canonical SDK builders and
projections retain their existing behavior; the added
`credentialVerificationSupported` field is tested separately. Ordinary agent
discovery does not use these internal gateway policy descriptors.

Keep these expected values fixed when changing the module. They check common
configuration in core and canonical action, scope, credential and upstream
metadata in the linked Git module. The fixture omits egress proxy settings;
separate proxy tests own that configuration and transport coverage.
