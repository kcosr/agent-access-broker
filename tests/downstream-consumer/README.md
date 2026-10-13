# Independent downstream consumer

This fixture checks that the provider SDK and the Broker host can be consumed
the way another team would consume them: a separately owned provider repository
and a downstream Broker distribution, each with its own manifests, lockfile and
full-revision pins, built from a clean staged source set without access to this
checkout's workspace, target directory or lockfile.

`scripts/verify-downstream-consumer.mjs` stages and runs it. Release
qualification runs the same driver as its required `downstream-consumer` gate.

## Templates

The two directories here are templates, not crates of this workspace. The root
`Cargo.toml` excludes this directory, and each template has its own workspace
root.

- `provider-repo/` is the workspace root of the provider repository. The driver
  adds the maintained `crates/agent-access-conformance` crate from the candidate
  commit with `git archive`; there is no second provider implementation. Only
  Cargo metadata is normalized: the crate's path dependency on
  `agent-access-provider` becomes the provider repository's own pin, and the
  driver appends the third-party `[workspace.dependencies]` entries the crate
  inherits, copied verbatim from the candidate root manifest. The provider
  repository versions its crate independently (`0.7.0`).
- `assembly-repo/` is a downstream distribution, `downstream-broker` `0.3.0`,
  following the [downstream assembly guide](../../docs/downstream-assembly.md).
  It links `agent-access-broker-host` and production `agent-access-cloudbees-ci`
  from upstream and `agent-access-conformance` from the provider repository.
  Its library exports `composition()`, which selects CloudBees CI and the
  development-only conformance provider, and `build_identity()`; `main.rs`
  runs the host's `BrokerApplication` with both.
  - `build.rs` reads the assembly's own `Cargo.lock` and emits the locked
    version and full commit of the upstream and provider repositories. The
    identity reports them as evidence-backed revisions: the upstream commit for
    the host, the SDK and CloudBees CI, and the provider commit for the
    conformance module, in a module provenance map keyed by crate name and
    version.
  - The assembly's own revision and qualification label come from
    `DOWNSTREAM_BROKER_REVISION` and `DOWNSTREAM_BROKER_QUALIFICATION` at build
    time, which only the process that builds and qualifies a verified clean
    checkout sets. The driver sets them to the staged assembly commit and
    `downstream-consumer`; without them the assembly reports an unavailable
    revision and `unqualified`.
  - Its tests check the composition, the reported identity and locked sources,
    that provenance for an unregistered package is rejected, and, with the
    host's `test-support` feature as a development dependency only, serve the
    same status from an `IsolatedBroker`.

Every manifest names upstream crates exactly as a downstream repository must:
`git = "https://github.com/kcosr/agent-access-broker.git"` with `rev` set to a
full 40-character commit. The templates carry the all-zero sentinel revision;
the provider repository uses the reserved example URL
`https://git.example.com/provider-team/conformance-provider.git`. Path
dependencies, branches, tags, abbreviated revisions and alternate URL spellings
are rejected. Cargo reads every manifest in a Git checkout, so the templates stay
valid TOML and their package names never repeat an upstream package name. Both
templates pin the repository toolchain and build with `debug = false` and
`incremental = false`.

## Running

From a clean checkout at the commit under test:

```bash
node scripts/verify-downstream-consumer.mjs --commit "$(git rev-parse HEAD)" \
  --evidence-dir /absolute/new/evidence/directory
```

The evidence directory must be new or empty and outside the checkout. Every
crates.io package in `Cargo.lock` must already be in the shared Cargo download
cache (`$CARGO_HOME/registry/cache`, by default `~/.cargo`); run
`cargo fetch --locked` in the checkout first if it is not. The driver never
downloads crates. The stage is created under `$TMPDIR`; no Cargo configuration
file may exist in `.cargo` directories above it.

## What the driver checks

1. The checkout is clean at the explicit full `--commit`.
2. It creates a private stage under `$TMPDIR` (mode `0700`) and clones the
   repository with `git clone --bare --no-local --no-hardlinks`. The clone has no
   alternates file and no remote; it advertises only a detached `HEAD` and
   `refs/heads/candidate` at the candidate commit.
3. It builds the candidate's `agent-access` CLI in the stage from `git archive`
   of the candidate commit, so the CLI used for acceptance is bound to that
   commit; `status.json` records its digest.
4. It builds the provider repository and the assembly as two local Git
   repositories from `git archive` of the candidate. Only staged manifests are
   rewritten: the canonical upstream URL becomes the clone's `file://` URL, the
   provider URL becomes the provider repository's `file://` URL, and each
   sentinel becomes the matching full commit. `source-mapping.json` records every
   rewrite.
5. Each staged `Cargo.lock` is seeded with the candidate's third-party entries.
   A setup `cargo fetch` adds the Git packages; the provider repository is
   committed with its lockfile before the assembly pins it.
6. The lockfile review requires every upstream package to resolve to
   `git+file://<stage>/upstream?rev=<sha>#<sha>`, the conformance crate to
   resolve only to the provider repository, exactly one `agent-access-provider`
   package ID across both graphs, no path or registry copies of upstream
   packages, and third-party entries equal to candidate entries, including
   checksums.
7. The provider repository runs its own unit tests with SDK `test-support`, and
   its resolved graph, including development dependencies, contains no core,
   host, assembly, CLI or import-adapter crate.
8. The assembly passes `rustfmt --check` and `cargo test`, then `cargo build`
   builds the executable last, so it carries no development features; `cargo
   tree -e normal,build,features` shows no `test-support` feature in its release
   graph although its tests enable the host's.
9. Process acceptance starts the built assembly executable with a generated
   development configuration: CloudBees CI pointed at a synthetic loopback
   controller, the conformance provider configured, a synthetic static
   principal and a synthetic `basic_api_token` credential. It checks that the
   same configuration without `enable_fake_service` exits 3, readiness and
   health, and that `/v1/broker/status` needs identity. The status must equal
   the identity the driver derives independently: the assembly's name, version,
   label and commit, the host and SDK at the upstream commit, CloudBees CI and
   conformance with their roles at the upstream and provider commits, all
   evidence-backed, and the inventory fingerprint recomputed from those fields;
   the `broker_starting` event must carry the same identity and fingerprint.
   It then checks one granted `cloudbees_ci.build.log.read` through the staged CLI
   with the controller receiving the expected Basic credential, an ungranted
   job's denial, SIGTERM shutdown with exit 0, and the allow and deny audit
   records.
10. It copies the staged manifests and lockfiles, logs, cargo trees, lock
    review, acceptance outputs and `status.json` into the evidence directory and
    deletes the stage.

All Cargo commands after setup use `--locked --offline`, and builds name an
explicit target directory inside each staged repository.

SIGINT or SIGTERM stops every child process tree the driver started (Cargo and
its compilers, the broker, the CLI), closes the synthetic controller, records
the interruption in `status.json` with the evidence gathered so far, removes the
stage, and exits with 128 plus the signal number.

### Offline dependency source

The staged repositories use a private Cargo home inside the stage. Its
configuration replaces crates.io with a Cargo `directory` source that the driver
builds from the shared download cache: for every crates.io entry in the
candidate `Cargo.lock`, it finds the `.crate` archive in
`$CARGO_HOME/registry/cache`, checks its SHA-256 against the lockfile checksum,
and extracts it with a `.cargo-checksum.json` carrying that checksum. A missing
or mismatched archive fails the run before Cargo starts, and Cargo has no
network registry to fall back on. The shared cache is read but never written.

Cargo fetches Git dependencies into the private Cargo home through the Git CLI
(`net.git-fetch-with-cli`), and every Git command runs with system and global
Git configuration disabled, an empty stage-owned home and
`GIT_ALLOW_PROTOCOL=file`, so user URL rewrites or credential helpers cannot
redirect the staged `file://` sources and no network transport is available.
Inherited Cargo, compiler and broker environment variables are removed.

Cargo also reads configuration files from `.cargo` directories above the
directory it runs in. Before Cargo first runs in a staged repository, any
configuration file other than the private one that would apply there fails the
run, whatever it contains, because sources, patches, includes, artifact
directories and runners could all change what is built.

## Canonical remote pins

`--source canonical` keeps the canonical upstream URL and pins it to the full
candidate commit, so Cargo fetches upstream from the published repository. Use
it only after the candidate commit is published; the provider repository stays
local, Git may then also use `https`, and crates.io packages still come only
from the shared download cache.

## Not covered

Portal assets are not served or checked; a downstream distribution builds or
consumes them from the pinned upstream commit.
