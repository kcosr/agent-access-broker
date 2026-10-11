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
