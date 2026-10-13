# Supported public API inventory

This directory holds the checked-in inventory of the supported Rust API, one
generated text file per surface. Never edit the `.txt` files by hand; regenerate
them with `scripts/public-api.mjs` and review the diff.

## Surfaces

| File | Surface |
| --- | --- |
| `agent-access-provider.txt` | The provider SDK with its default features. |
| `agent-access-provider.test-support.txt` | The SDK with its `test-support` feature. |
| `agent-access-broker-host.txt` | The Broker host with its default features. |
| `agent-access-broker.txt` | The assembly library: `composition()` and everything else it exports. |
| `<native or adapter crate>.txt` | The crate's reviewed selection entry points only. |

The surfaces come from each workspace crate's `[package.metadata.agent-access]
role`. SDK and host crates are inventoried with their default features and, when
they declare it, with their `test-support` feature (`<crate>.test-support.txt`).
Native and import adapter crates that the assembly links are restricted to the
root exports listed in `SELECTION_ENTRY_POINTS` in `scripts/public-api.mjs`:
their backend, OAuth dialect and import adapter registrations. The check fails
until every such crate has reviewed entry points, and rejects entry points for any
other crate. Core, helper, reference and CLI crates have no surface of their own.

Each file has up to three parts:

- The surface's items as `cargo-public-api` lists them: one line per item,
  including inherent, trait, derived and auto-trait implementations. Blanket
  implementations and function parameter names are omitted.
- `Exposed through supported signatures` sections. These list workspace items
  that the surface's signatures, bounds, fields, implementations or re-exports
  name, directly or through other exposed items, and that no inventoried
  surface already covers. Core and helper crates are supported only to this
  extent. Exposed items appear under their defining module path, which may not
  be nameable from outside the crate.
- `Public dependency packages`: third-party packages whose items appear in the
  file, with their semver-compatible lines, such as `http 1` or `reqwest 0.12`.

Signatures name other crates' items by their defining module path, as rustdoc
records them, for example `agent_access_provider::backend::BackendRegistration`.
Moving an item between private modules therefore changes these lines without
changing the API; review such a change as a move.

## Commands

```bash
node scripts/public-api.mjs check
node scripts/public-api.mjs update
```

`check` regenerates every surface in memory and compares it with the checked-in
files. It exits with status 1 and prints a summary and unified diff when a file
differs, a surface is missing, or a checked-in file is no longer generated.
`update` prints the same summary and rewrites the `.txt` files. Commit the
result only after reviewing it against the rules below.

## Prerequisites

- The `nightly-2026-07-13` Rust toolchain installed with rustup, which provides
  the rustdoc JSON format 60 that the inventory requires. Install it with
  `rustup toolchain install nightly-2026-07-13 --profile minimal`.
- `cargo-public-api` 0.52.0 on `PATH`. Install it with
  `cargo install cargo-public-api --version 0.52.0 --locked`.

If the nightly is in a different rustup home from the active one, set
`AGENT_ACCESS_PUBLIC_API_RUSTUP_HOME` to that directory, for example
`AGENT_ACCESS_PUBLIC_API_RUSTUP_HOME="$HOME/.rustup"`. Otherwise the script uses
`RUSTUP_HOME`, then `~/.rustup`. A missing or mismatched tool fails with exit
status 2 and an installation hint; the check never skips.

## How the inventory is generated

The script resolves the nightly's `cargo`, `rustc` and `rustdoc` with
`rustup which --toolchain nightly-2026-07-13` and runs them by absolute path,
with `RUSTUP_TOOLCHAIN` set to the nightly. The repository's
`rust-toolchain.toml` and the active toolchain therefore do not apply. It clears
inherited target directories, compiler wrappers and Rust flags, caps lints, and
builds only in `target/public-api`, leaving the normal development and release
targets untouched. For each crate and feature set it runs the equivalent of:

```bash
cargo +nightly-2026-07-13 rustdoc --locked -p <package> --lib \
  --target-dir target/public-api --no-default-features [--features <features>] \
  -- -Z unstable-options --output-format json --cap-lints allow
```

`cargo tree -e normal`, with the surface's default and requested features,
supplies the features Cargo activates for the surface and each of its
dependencies, including local features that other features enable, and the
versions of public dependencies. Generation, coverage and exposure use these
expanded feature sets; a surface's file name uses only its requested feature.
Selection surfaces and exposed sections are rendered from restricted copies of
the rustdoc JSON. Every surface is rendered with:

```bash
cargo-public-api --rustdoc-json <file.json> --color never --omit blanket-impls
```

This reads the JSON file directly; `cargo-public-api` neither builds nor checks
out any revision. The inventory covers the native host target's configuration.

## Baseline and review rules

Release qualification runs the required `public-api` gate, which is `check` on
the candidate. It proves that the candidate's API matches its own checked-in
inventory, so every API change was regenerated and reviewed with the change that
made it. It does not compare with an earlier release.

`0.2.0` is the first released baseline. `0.1.0` predates the inventory; the
changelog documents the intentional changes since then.

Within a compatible release line, compare the candidate with the previous
release's inventory, for example `git diff v0.2.0 -- api/`:

- A patch release must not remove or change any line. Removals and changes to a
  signature, bound, trait method, implementation, feature-gated item or public
  dependency line are breaking.
- Review every added line. A new required method on an implementable trait, such
  as `Provider`, `BackendConfig` or `OAuthDialect`, is breaking. A new default
  method is compatible only if it preserves the documented semantics. A new
  variant of an exhaustive enum or a new public field of an exhaustive struct is
  breaking.
- An incompatible change advances the minor version on the 0.x line and
  documents the required source and behavior changes in the changelog.

The inventory is a compile-surface record. It does not replace descriptor,
lifecycle or feature-behavior checks, which the test suites and release
qualification cover.
