# Shared UI source and contributions

The portal includes a committed source snapshot of
[`kcosr/workbench-ui`](https://github.com/kcosr/workbench-ui) in
[`apps/portal/src/workbench`](../apps/portal/src/workbench). The upstream
repository is currently private. Ordinary installs, builds and tests use the
committed snapshot and public npm dependencies; they need no sibling checkout,
private registry or upstream access. Broker does not depend on an npm package
named `workbench-ui` or `workbench-ui-kit`.

[`VENDORED.md`](../apps/portal/src/workbench/VENDORED.md) records the upstream
commit, and [`VENDORED.json`](../apps/portal/src/workbench/VENDORED.json) records
the copied file hashes. The current pin is
`8518a257617f81eab4a974105a5cc42153763c69`. The copied components, helpers and
styles originated in `kcosr/gh-dash` and were extracted into the shared kit.
The snapshot also includes the kit's MIT `LICENSE`, local fonts and a portable
verifier.

## License and distribution

The kit-authored source in this Broker distribution is covered by the root
[MIT license](../LICENSE). The root [NOTICE](../NOTICE) records the source pin
and preserves the MIT copyright and permission notice for the gh-dash-derived
portions. Inter and JetBrains Mono keep their separate SIL Open Font License
notices in the snapshot's `fonts` directory. This describes the rights and
notices for the Broker distribution; upstream repository access is separate.

Every portal production build includes these notices and the bundled JavaScript
and Tailwind CSS dependency notices in `dist/licenses`. Preserve the whole
directory when copying assets. See the
[portal build instructions](../apps/portal/README.md) for the distribution check.

## Proposing a shared component change

Public contributors can open an issue in the Broker repository, or attach a
proposed patch to an issue or pull request, with reproduction steps, the affected
component, and the desired behavior. No upstream access is required. Keep the
vendored directory unchanged in the submitted Broker tree; attach a proposed kit
diff as review material when useful. Portal integration changes outside the
snapshot can be submitted as ordinary Broker changes.

A maintainer with kit access reviews the proposal, implements and commits the
shared change upstream, and brings the updated snapshot into the Broker change.
The maintainer shares the resulting source diff and pin in the Broker review so
contributors can review and test the result here. The snapshot's instruction to
re-vendor describes that maintainer step, not a prerequisite for reporting or
proposing a fix.

Anyone with this checkout can run the portable integrity check:

```bash
npm --prefix apps/portal run check:workbench
```

Builds and unit tests also run this check. It detects added, missing or modified
snapshot files against the committed manifest. It does not independently prove
upstream authenticity if both source and manifest are changed.

## Maintainer update procedure

Use a kit checkout with both the recorded source commit and the intended new
commit available in Git history. Commit the kit's `src/` and portable verifier
before vendoring; the update script rejects uncommitted changes in those paths.
From the kit checkout, use the absolute Broker snapshot destination:

```bash
node scripts/vendor.mjs /absolute/path/to/agent-access-broker/apps/portal/src/workbench --check
node scripts/vendor.mjs /absolute/path/to/agent-access-broker/apps/portal/src/workbench
node scripts/vendor.mjs /absolute/path/to/agent-access-broker/apps/portal/src/workbench --check
```

The first check compares the existing snapshot with its pinned upstream Git
revision. The update refuses consumer drift and stages the replacement with
rollback on failure. Preserve and investigate reported drift before proceeding.
Do not edit generated provenance or checksum entries to bypass a refusal.

Review the complete copied diff, keep `.gitattributes`, the kit `LICENSE` and
both font notices, and update the source pin in this document and the root
`NOTICE`. Run the portal unit, build and browser checks from the
[testing guide](testing.md). Commit the whole snapshot update with the Broker
integration changes. Upstream access is needed only for this maintainer
procedure.
