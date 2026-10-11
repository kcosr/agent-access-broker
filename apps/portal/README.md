# Management portal

The portal is the broker's same-origin browser interface at `/ui`. Administrators
manage accounts, groups, grants, resources and imported services, inspect audit
events, and reload configuration. Auditors use the same administrative views
with read-only controls. Service policy managers work within their assigned
services. Personal tokens, credentials and connections require the account's
independent self-service setting.

Deployment and day-to-day administration are covered in the
[operator guide](../../docs/operator-guide.md),
[role reference](../../docs/roles.md) and
[end-user guide](../../docs/end-user-guide.md). Use the
[release checklist](../../docs/release-readiness.md) before distributing a build.

## Build and serve

Use a Node.js version supported by the locked Vite and Vitest dependencies
(Node 20.19+, Node 22.12+, or Node 24+). Install from the committed lockfile:

```bash
npm --prefix apps/portal ci
npm --prefix apps/portal run build
```

Run these commands from the repository root. The shared UI snapshot is committed;
no private upstream or sibling checkout is needed. See
[shared UI source and contributions](../../docs/workbench-vendoring.md).

Copy the complete `apps/portal/dist` directory, including its `assets` and
`licenses` directories, into the deployment package. The
broker serves it when browser authentication and the portal are enabled:

```toml
[portal]
enabled = true
mount_path = "/ui"
static_dir = "/opt/agent-access-broker/portal"
```

`static_dir` must be absolute. Configure browser authentication, management,
database paths and encryption keys using the operator guide. Deploy portal
assets and broker binaries from the same source revision. Vite's preview
server serves frontend assets; use the broker to exercise authenticated
administration workflows.

## Distribution notices

Production builds generate `dist/licenses/THIRD-PARTY-NOTICES.txt` from the
modules in the emitted JavaScript chunks, including transitive dependencies and
the Vite/Rolldown runtime helpers. The reviewed CSS-source inventory also includes
Tailwind's full MIT notice because `src/styles.css` imports its theme and utilities.
Keep this inventory aligned with stylesheet imports when changing CSS dependencies.
It retains each package's full license and copyright text. The build fails for a
missing MIT notice, unreviewed license identifier or unknown virtual runtime
module. The generator targets the locked
Vite 8/Rolldown interface; review its hooks and notice coverage when upgrading
the bundler. Build-only dependencies that contribute no shipped code are omitted.

The same directory includes the Inter and JetBrains Mono font notices,
`LICENSE-Agent-Access-Broker.txt`, `NOTICE-Agent-Access-Broker.txt`, and
`THIRD-PARTY-MANIFEST.json` recording package versions and file digests.
The normal build validates these files. Validate a copied deployment directory
with the same check:

```bash
npm --prefix apps/portal run check:notices -- /absolute/path/to/packaged/portal
```

The check requires the recorded notices and emitted JavaScript/CSS files to be
present and unchanged, and rejects extra JavaScript/CSS files. HTML, font and
image payloads are outside this check; cover them with the release package's file
checksums. The manifest verifies packaging integrity, not artifact authenticity.

## Validate changes

```bash
npm --prefix apps/portal run test:unit
npm --prefix apps/portal run test:e2e
```

Unit checks include notice-generator regressions and a production bundle notice
check. The browser harness uses local Cargo by default to build the broker and
CLI with locked dependencies into the repository's `target/<host>/debug`, then
starts isolated fixtures. The host triple comes from `rustc -vV`; the build
passes both `--target-dir target` and `--target <host>`, overriding inherited
Cargo target directories and cross-target settings. Fixtures select that same
native path. Chromium must be installed for Playwright.

The remote build service is optional:

```bash
BUILD_SERVICE_ENABLED=true BUILD_SERVICE_ENDPOINT="${BUILD_SERVICE_ENDPOINT:?Set your build-service URL}" \
  npm --prefix apps/portal run test:e2e
```

To reuse freshly built binaries from the selected source revision, set absolute
paths in both `AAB_BROKER_BIN` and `AAB_CLI_BIN` before running `test:e2e`; both
overrides skip the Rust build and require no Rust toolchain lookup. A single
override builds the remaining binary for the native host target.
`AAB_PORTAL_DIST` optionally selects another complete asset directory. The
independent delegated OAuth browser fixture requires
`OAUTH_STUB_REPO`; its test is skipped when that checkout is unavailable. See
[testing](../../docs/testing.md) for fixture setup and coverage.

For a disposable local walkthrough, use the
[managed demo](../../demo/README.md). The demo uses synthetic upstream credentials
and generates unique sign-in passwords in an owner-readable runtime handoff file;
it is a local evaluation environment.
