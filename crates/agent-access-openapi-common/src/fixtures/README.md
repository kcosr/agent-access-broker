# Gateway V1 durable contracts

The compact JSON files freeze the first-release `GatewayPlanV1` and
`GatewayRouteManifestV1` wire bytes. `v1-source.json` is a synthetic owner document
compiled separately with anonymous and static header-key authentication. The
route manifest also retains the earlier `/items/admin` operation as an inactive
denial guard after its removal from the current source.

`v1-hashes.json` records SHA-256 for both the typed wire bytes and the canonical
JSON-value bytes used inside generic persistence envelopes. Store-owned envelope
hashes and accepted-action-definition hashes have separate core fixtures.

These are historical contracts. Future refactors must read them unchanged;
introduce a new wire version when semantics change. Do not regenerate these
vectors to make a refactor pass.
