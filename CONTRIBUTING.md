# Contributing

Focused bug reports, bug fixes, and documentation improvements are welcome.

## Report a bug

Search the existing [issues](https://github.com/kcosr/agent-access-broker/issues)
before opening a new one. Include:

- The version or commit, platform, and affected integration or access path.
- What you expected, what happened, and a small set of reproduction steps.
- Relevant configuration and error output, with credentials and private data
  removed. Use synthetic names and example hosts where possible.

Keep each issue focused on one problem. A minimal reproduction is more useful
than a full deployment configuration or an unfiltered log archive.

## Submit a focused fix

A small, well-scoped fix can be submitted directly as a pull request; a separate
issue is helpful when the problem needs discussion. Link the issue when one
exists and explain the behavior before and after the change.

- Address one bug or documentation problem per pull request. Keep unrelated
  refactoring, formatting, dependency upgrades, and feature work separate.
- Add a regression test when it meaningfully demonstrates a behavior fix.
  Documentation-only corrections do not need new runtime tests.
- Update affected documentation, samples, and supported interfaces together.
- Report the checks you ran and their results, including any checks you could
  not run and why.

Read [AGENTS.md](AGENTS.md) for repository conventions and required development
checks. The [testing guide](docs/testing.md) explains the test suites, fixtures,
and optional live-provider checks. Use the pinned toolchain and locked
dependencies documented there.

Run the Rust tests with `cargo nextest run --locked --workspace`, then run
doctests with `cargo test --locked --workspace --doc --no-fail-fast`.
The [testing guide](docs/testing.md#local-deterministic-suite) documents the
required nextest version, concurrency controls, and the supported plain-Cargo
command.

The portal includes a committed shared UI snapshot. Keep that snapshot unchanged
in a normal Broker pull request; propose shared component fixes through the
[UI contribution workflow](docs/workbench-vendoring.md). Application changes
outside the snapshot can follow the ordinary pull-request process.

## Propose a feature

Open an [issue](https://github.com/kcosr/agent-access-broker/issues) for a focused
feature request with a clear use case. Start a
[GitHub Discussion](https://github.com/kcosr/agent-access-broker/discussions) for
larger ideas, substantial changes, or proposals whose fit with the project needs
discussion.

Describe the problem and intended users, the current limitation, and the behavior
you would like to see. Concrete workflows and examples help more than a list of
implementation details.

Discuss the scope and fit before investing in a larger implementation. For a new
integration or access-control feature, explain the service, required actions,
credential model, and resource boundaries involved. Keep feature proposals
separate from bug-fix pull requests so each can be reviewed on its own merits.

## Contribute a provider

A native provider does not need to live in this repository. You can keep it in
your own repository, depend on the provider SDK by a pinned upstream revision,
and build your own distribution that links it; that needs no upstream change.
The [provider SDK guide](docs/provider-sdk.md) describes the supported
interfaces, the trust model and a worked example, and the
[downstream assembly guide](docs/downstream-assembly.md) covers composition,
identity, pinning and qualification.

Propose a provider for this repository through a feature discussion first.
An accepted first-party provider is a `crates/agent-access-<service>` crate
whose manifest declares `role = "native"`. It depends only on the SDK and
helper libraries, never on core, the host, an assembly, the CLI or an import
adapter. The pull request also:

- selects its registration in `crates/agent-access-broker/src/backends.rs` and
  adds its package to the module provenance list in
  `crates/agent-access-broker/src/build_info.rs`;
- adds its registration to the reviewed selection entry points in
  `scripts/public-api.mjs` and commits the regenerated `api/` inventory;
- adds `docs/providers-<service>.md`, links it from
  [providers.md](docs/providers.md) and the README integration table, and
  updates the configuration reference and sample configuration;
- includes unit tests built with the SDK's `test-support` feature and an
  offline Broker/CLI smoke against a stubbed upstream.

Propose changes to the SDK itself as a feature request with the provider use
case. Supported interfaces follow the guide's
[compatibility policy](docs/provider-sdk.md#compatibility-policy).
