# Release readiness

Prepare release metadata for review, qualify the final source commit, and publish
that exact qualified commit. This guide also covers distribution and administrator
acceptance. It describes required checks; only the recorded results establish
which checks a candidate passed. Preserve the exact commit, commands, results,
and limitations with each qualification.

Preparation, qualification, provenance verification, and publication reject
nonempty inherited Git location/index/object/configuration overrides, including
`GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, and `GIT_CONFIG_*`. Unset these
before release work. Each entrypoint verifies that Git's actual repository root
matches the source checkout it operates on.

## Select the release

- Select a clean, reviewed commit and the intended workspace version. Ship the
  broker, CLI, and portal from the same revision. Catalog v2 requires a coordinated
  broker/CLI upgrade; do not reuse an older CLI or portal asset directory.
- Review the [release notes](../CHANGELOG.md), the current
  [database migration contract](database.md), and the installed configuration.
  Remove obsolete fields before validation. Back up existing managed and audit
  databases and all required keys before starting a newer binary.
- Plan the [upgrade and rollback](operator-guide.md#upgrade-and-rollback) together.
  An older binary may reject an upgraded database; restore the matched pre-upgrade
  configuration, state, keys, binaries, and portal when rollback requires it.

## Prepare release metadata

The initial `0.1.0` release metadata is already prepared in this source tree.
After review and merge, proceed to qualification; do not run `current` again
for an already prepared version. For subsequent releases, start from a clean
checkout on a preparation branch and select `current`, `major`, `minor`, `patch`,
or an explicit version:

```bash
node scripts/prepare-release.mjs patch
```

Use `current` only when the workspace already has the intended version and its
release notes still need preparation. The script edits only `Cargo.toml`,
`Cargo.lock`, and `CHANGELOG.md`, stamps the release notes, and opens an empty
`Unreleased` section in the same change. It validates locked Cargo metadata and
restores the three files if preparation fails. Review and commit the change,
then merge it through the normal PR process. Preparation performs no commits,
tags, pushes, or publication.

## Qualify the candidate

Use the pinned Rust/Cargo 1.98.1 toolchain in `rust-toolchain.toml`, Node.js 24.18.0,
npm 11.16.0, and Python 3.11 or newer. The tested toolchain versions do not
establish minimum supported Rust or Node.js versions. Python's `sqlite3` module
must use SQLite 3.43 or newer with FTS5 `contentless_delete` support. Preflight
checks the version and exercises table creation, insertion, and deletion, so
required audit smoke coverage cannot silently skip on an older or feature-limited
SQLite build.

Preflight follows Cargo configuration includes and rejects configured target
runners so native Rust tests execute directly. This check does not fully attest
other Cargo configuration or the native build environment; the
[provenance limits](operator-guide.md#build-provenance-and-deployed-status) still
apply.

From the final clean merged commit, run:

```bash
node scripts/verify-release.mjs --output-dir /absolute/external/path
```

The output directory must be new or empty and outside the checkout. The driver
runs the required standalone Rust, crate-boundary, portal build/unit/browser,
script, documentation, sample-config, Unix signal, native release-provenance, and
notice checks. It writes `qualification.json`, per-gate logs, and native Rust notices.
It fails on missing required prerequisites or failed gates; unavailable required
checks cannot become a passing qualification. Optional OAuth/live-provider
exclusions and platform applicability are recorded explicitly.

The driver accepts any clean branch or detached commit for PR validation and
rechecks that the source stays clean at the same full SHA throughout the gates.
A merge that changes the SHA needs a new qualification of the merged commit.
Qualification builds natively and locally. The separate optional remote
provenance verifier does not replace this qualification. The driver creates
local evidence; it does not commit, tag, push, publish, package archives, or run
administrator acceptance against a deployment.

### Required check scope

The commands below explain the qualification gates and help diagnose failures.
The qualification driver supplies the validated toolchain and explicit native
artifact paths. Running individual checks does not create the passing
`qualification.json` required by the publisher.

```bash
cargo fmt --check
cargo test --locked
BROKER_BUILD_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
cargo build --locked --target-dir target --target "$BROKER_BUILD_TARGET"
cargo clippy --locked --all-targets --all-features -- -D warnings
npm --prefix apps/portal ci
npm --prefix apps/portal run build
npm --prefix apps/portal run test:unit
node --test scripts/*.test.mjs
node scripts/check-crate-boundaries.mjs
python3 scripts/generate-rust-notices.test.py
python3 scripts/release-prerequisites.test.py
python3 scripts/local-broker-process.test.py
python3 demo/seed-audit-showcase.test.py
node scripts/check-doc-links.mjs
```

On Unix, also run the required isolated real-signal parent fixture:

```bash
cargo test --locked -p agent-access-broker-host --lib lifecycle::tests::unix_signal_smoke_in_isolated_child_processes -- --ignored --exact
```

It tests SIGTERM/SIGINT shutdown and SIGUSR2 reload without live credentials.
The guarded child entrypoint remains ignored and must only run through the
parent. Do not use a broad `-- --ignored`, which also selects live smokes.
Qualification requires exactly one passing parent test, and the parent checks
that each child actually ran; an empty exact-name match fails the gate. Record
this fixture as not applicable on non-Unix platforms. Portal unit and browser
configurations also reject focused-only tests so they cannot silently narrow
the required suites.

Run the portal browser suite against the native candidate binaries produced by
the explicit build above. The target directory and host triple keep inherited
Cargo target settings from selecting an older artifact:

```bash
AAB_BROKER_BIN="$PWD/target/$BROKER_BUILD_TARGET/debug/agent-access-broker" \
AAB_CLI_BIN="$PWD/target/$BROKER_BUILD_TARGET/debug/agent-access" \
npm --prefix apps/portal run test:e2e
```

The browser suite requires its Playwright Chromium installation and system
libraries. See [testing](testing.md) for setup and exact test scope. Report an
unavailable dependency or environment-restricted test explicitly; do not claim
untested workflows passed. Live provider tests require separately configured
accounts and approved test resources. Run them only with the individually named
commands in the testing/provider guides; deterministic tests alone do not prove
compatibility with every upstream deployment.

Validate all three published configuration templates:

```bash
"target/$BROKER_BUILD_TARGET/debug/agent-access-broker" \
  --config agent-access-broker.sample.toml config validate
"target/$BROKER_BUILD_TARGET/debug/agent-access-broker" \
  --config agent-access-broker.production.sample.toml config validate
"target/$BROKER_BUILD_TARGET/debug/agent-access" --config agent-access.sample.toml config validate
```

Configuration validation checks schema and supported local validation rules.
It does not create a managed store, bootstrap an administrator, test a user's
credential, or prove the production ingress is secure. Complete a fresh-store
bootstrap test and an upgrade/restore rehearsal using a protected copy of existing
state when accepting an upgrade.

Complete qualification against the final clean candidate commit and freshly
built Broker, CLI, and portal from that commit. Preserve the receipt, each command
and exit code, source revision, toolchain, and limitation. Retain failed-run
evidence alongside accepted reruns. Further candidate edits or a different merge
SHA require new qualification. Keep optional OAuth/live-provider results and
platform-specific exclusions distinct from the required standalone gates.

## Build and distribute

Production builds require immutable provenance. Follow
[build provenance](operator-guide.md#build-provenance-and-deployed-status) and
verify the broker's authenticated status from a clean checkout at the chosen
commit or exact tag. A development build that reports `unavailable` provenance is
not a verified production artifact. Qualification already runs this native local
check; it can also be run independently:

```bash
node scripts/verify-release-provenance.mjs <full-commit-or-exact-tag>
```

The local verifier checks the exact pinned compiler/Cargo versions and physical
paths, rejects ambient compiler/flag/profile overrides, rejects any `test-support`
feature or `reference` crate in the release dependency graph, and builds both
native executables under `target/<host-triple>/release` with locked
dependencies. It checks CLI startup and authenticated Broker status and records
discovered Cargo configuration digests. These are bounded provenance checks, not a hermetic-build
attestation; configuration includes, profile/linker settings, native tools,
build scripts, and system libraries are not fully attested. See the
[operator guide](operator-guide.md#build-provenance-and-deployed-status) for the
full contract. The optional `--build-service` check leaves remote compiler/Cargo
and service configuration unverified and cannot replace local qualification.

The release delivery must contain:

- The freshly built `agent-access-broker` and matching `agent-access` executables.
- The complete `apps/portal/dist` directory, including its `index.html`, hashed
  assets, and `licenses` directory, served from the configured `portal.static_dir`.
  Preserve `THIRD-PARTY-NOTICES.txt`, `THIRD-PARTY-MANIFEST.json`,
  `LICENSE-Agent-Access-Broker.txt`, `NOTICE-Agent-Access-Broker.txt`,
  `LICENSE-Inter.txt`, and `LICENSE-JetBrainsMono.txt` under `licenses`.
- The production broker and CLI sample configurations, administrator/operator/user
  guides, changelog, root `LICENSE` and `NOTICE`, and generated Rust executable
  `THIRD-PARTY-NOTICES.txt` and `rust-dependencies.json`.
- The source revision, platform/toolchain, build instructions, checksums, and
  validation results or limitations needed to identify and verify the package.

Using Python 3.11 or newer on the native release build host, generate Rust notices
for that host's target triple after the locked release build, then check both
notice sets in the assembled package. The `--target` value must equal the host
reported by `rustc -vV`; cross-compilation notice generation is unsupported:

```bash
python3 scripts/generate-rust-notices.py --target <rust-target-triple> --output-dir /absolute/path/to/package
python3 scripts/generate-rust-notices.py --target <rust-target-triple> --output-dir /absolute/path/to/package --check
npm --prefix apps/portal run check:notices -- /absolute/path/to/package/portal
```

The Rust inventory follows Cargo metadata from Broker and CLI production roots,
excludes dev dependency edges, and labels normal and build/proc-macro dependency
paths separately. Workspace feature unification can conservatively include unused
crates or features; this is not an exact static-link inventory. It uses locked,
offline native-platform metadata and cached source license files. Run
`cargo fetch --locked --target <rust-target-triple>` first if sources are missing.
Missing licenses, changed supplemental records, and stale output fail the check.
Review pinned supplemental notices when updating dependencies. The inventory does
not cover the Rust standard library/toolchain, system libraries, portal assets,
or separately distributed executables; assess their notices for the package too.

Portal notice validation checks required notice files and the emitted JavaScript
and CSS file inventory and digests. Use package file checksums to verify HTML,
font, and image payloads too. Preserve both generated notice sets in the final
distribution and repeat the checks after extraction. See
[shared UI source and licensing](workbench-vendoring.md) for snapshot provenance.

Keep credentials, private configuration, databases, logs, tokens, and compiler or
dependency caches out of distribution artifacts. Qualification creates evidence
and notices; archive assembly and extraction checks remain separate packaging
work. The publisher creates the source tag and release notes without attaching
a complete runtime package. Native Linux validation does not establish
compatibility with a different Linux distribution or architecture.

## Administrator acceptance

Follow the [operator guide](operator-guide.md) and
[administrator guide](administrator-guide.md) to verify the deployed environment:

1. Confirm the HTTPS origin, restricted HTTP listener, immutable portal assets,
   owner-only state/key directories, and required identity. Confirm `/v1/healthz`
   and `/v1/readyz`, then check authenticated broker status and provenance.
   Verify `network.trusted_proxies` names the exact ingress peers, ingress strips
   client-supplied forwarded-address headers and sets verified addresses, and
   audit distinguishes clients through that ingress. Confirm a client's failed
   logins do not lock out the same account from a different resolved source.
2. Bootstrap the first administrator, change its initial password, create a second
   recovery administrator, remove the bootstrap fields, and return
   `managed_store.auto_migrate` to `false` after successful startup/migration.
3. Add one integration, a narrowly scoped resource and read grant, a user-owned
   credential or approved service credential, and a finite invocation token.
   Verify one authorized read and one denied action/resource/context.
4. Verify that an auditor can inspect administration and audit but cannot mutate,
   reveal credentials, run credential verification, or discover an import.
   Verify a service policy manager can change only directly assigned services.
5. Pause or revoke the test token and confirm access stops. Confirm the audit trail
   contains the intended principal, context, decision, and request identifiers
   without passwords, execution credentials, or private resource attributes.
6. Verify a stopped-store backup and restore, audit verification, and restart.
   Confirm recovery retains principals, grants, encrypted credentials, and key
   readiness. Record the recovery owners and retention policy.

## Publishing

Only when publication is intended, use the passing qualification for the exact
prepared release commit:

```bash
node scripts/release.mjs --qualification /absolute/external/path/qualification.json
```

The publisher verifies the receipt's full SHA, version, and required gates. It
requires a clean `main` matching freshly fetched `origin/main` and that qualified
SHA. It creates an annotated tag at the qualified commit and pushes only the
tag, then creates and publishes a GitHub draft using the prepared version notes.
It does not edit source, commit, push `main`, or reopen the changelog after tagging.

If publication fails, matching tags and drafts are preserved. Retry with the same
qualification only when the existing tag and draft metadata match the same SHA,
version, and notes. Existing published releases are never overwritten. See the
[release procedure](../AGENTS.md#release-procedure). Preparation, qualification,
and publication do not deploy or restart a service.
