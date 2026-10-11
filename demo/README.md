# Managed Web Demo

Start or reseed the local managed portal demo:

```bash
./demo/start-managed-web-demo.sh
```

The launcher supports macOS and Linux. Install Rust/Cargo, Node.js/npm,
Python 3, `curl`, and `jq`, then run `npm --prefix apps/portal ci` before the
first launch. On macOS, also install the Xcode Command Line Tools. The launcher
builds a release broker and portal assets when they are missing. To reuse a
debug build or a custom Cargo target directory, set `AAB_DEMO_BROKER_BIN` to
the executable's absolute path. It checks port availability and the identity
of an existing broker without requiring Linux `ss`, `setsid`, or `/proc`.

Use:

- Web URL: `http://127.0.0.1:18787/ui`
- Admin principal: `admin`
- User principals: `alice@example.test`, `bob@example.test`, `viewer@example.test`
- Git gateway: `http://127.0.0.1:18788` with Host `git.demo.test`
- Generated tokens/env: `/tmp/agent-access-broker-demo/credentials.env`
- Agent token file: `/tmp/agent-access-broker-demo/alice-agent.token`
- Generated broker config: `/tmp/agent-access-broker-demo/agent-access-broker.toml`
- Generated CLI config: `/tmp/agent-access-broker-demo/agent-access.toml`

`AAB_DEMO_BASE`, `AAB_DEMO_PORT`, and `AAB_DEMO_GATEWAY_PORT` can isolate a
second demo instance. The script materializes both configurations under that
base, rewriting database, audit, upload-spool, portal, token-file, and CLI URL
settings. Tracked TOML files remain templates. Passwords and tokens are written
only to the owner-readable credentials file, not printed in startup output.
Source that file with Bash to load the generated environment; it contains each
principal's password, including the viewer account. Every reseed creates new,
independent random passwords by default. Explicit `AAB_DEMO_ADMIN_PASSWORD`,
`AAB_DEMO_ALICE_PASSWORD`, `AAB_DEMO_BOB_PASSWORD`, and
`AAB_DEMO_VIEWER_PASSWORD` values may be supplied through a private environment.
Supplied passwords must be distinct, contain 8–1024 bytes, and differ from their
principal IDs. The launcher safely quotes supplied values in the handoff file.
Avoid command-line arguments or shared shell history for password overrides.

The tracked broker template has an empty bootstrap-password placeholder and
cannot run directly. The launcher substitutes a fresh random initial password,
then replaces it with the administrator's generated or supplied sign-in password.

Each run wipes and reseeds `/tmp/agent-access-broker-demo` with demo users,
principal groups, four catalog resources, a mixed resource group, provider
grants, Git gateway grants, fake upstream credentials, and new tokens. Seeded grants and agent tokens use the finite
execution context `default`. The demo agent token follows current grants without
a service/resource ceiling. This loopback setup uses the supported direct-client
`default_context`. A deployment that uses trusted context assertions must make
the broker and Git-gateway listeners reachable only through ingress that strips
caller-supplied `X-Agent-Access-Context` and inserts the attested value. Configure
and verify those listener paths separately, and choose their context policy to
match that trust boundary.

The seeded `Demo resources` group contains the working fake `DEMO` project,
the `DEMO` Jira project, the `DEMO`
Confluence space, and `demo/app` repository. Grants select that group and use
only their applicable resource type. The same repository entry serves GitLab
REST and Git HTTP. Browse Resources to inspect coverage, contexts, and Used by.
The demo always creates a fresh database; existing policy records are not migrated.

Alice's GitLab grant uses her managed per-user credential for inline review
replies, draft-note CRUD/publication, and review submission. GitLab owns those
drafts and reviewer state under Alice's upstream identity. A production
operator may deliberately use a service credential for a bot reviewer, but all
principals sharing that bot then share its draft set.

The demo config intentionally raises the service invocation limit
(`[limits.invocations]`) and concurrency limits so browser walkthroughs and
Playwright capture passes do not trip production-oriented defaults. Stop it with:

```bash
kill "$(cat /tmp/agent-access-broker-demo/broker.pid)"
```


## Populate the audit screens

The sample audit seeder inserts 240 synthetic records spanning approximately
24 hours, with allowed, denied, and error outcomes across Jira, Confluence,
GitLab, the fake provider, and broker administration. Download and management
pairs share broker request IDs so request timelines have multiple events.
These are presentation fixtures: the seeder does not invoke upstream services
or change managed users, grants, credentials, or tokens.

Stop the demo, seed its audit database, and resume the retained state:

```bash
kill "$(cat /tmp/agent-access-broker-demo/broker.pid)"
python3 demo/seed-audit-showcase.py
./demo/resume-managed-web-demo.sh
```

The seeder refuses a running broker or an unsupported database schema, holds
both state locks while writing, and creates an owner-readable SQLite backup
beside the audit database. Repeating it replaces only records carrying its
`demo-showcase` marker. Use `--dry-run` to inspect fixture counts without writing
and `--demo-dir` for an isolated demo directory. Python 3 with SQLite 3.43 or
newer and `lsof` are required.

Open Audit and search for `demo-showcase` to isolate the samples. Download
records have `started` and `completed` phases; management records have
`preflight` and `success` phases. Search, service, principal, decision, and
reason filters operate on the same populated database as the portal.

`resume-managed-web-demo.sh` retains the database, generated configuration,
passwords, tokens, portal assets, and log. The initial launcher saves the
settings needed to resume in its private credentials file. Use the initial
`start-managed-web-demo.sh` only when you intend to wipe and reseed the demo.

## Capture showcase and walkthrough images

The capture script uses the real populated portal with separate browser
sessions for the administrator and Alice. Install Playwright Chromium first:

```bash
(cd apps/portal && npx playwright install chromium)
```

Load the private demo credentials in a Bash subshell and capture both streams:

```bash
(
  source /tmp/agent-access-broker-demo/credentials.env
  node demo/seed-guide-accounts.mjs
  AAB_CAPTURE_OUTPUT="$PWD/.scratch/portal-captures" \
    node scripts/capture-portal.mjs
)
```

The `showcase/` directory contains light and dark images for highlighting
policies, effective access, audit decisions, request timelines, and personal
access. The `guide/` directory contains only light-mode images for sequential
administrator and self-service walkthroughs. A JSON manifest records each
image's theme, viewport, and subject. Both streams use a 1440×960 viewport.

The online guide-account seeder adds `auditor@example.test` with the auditor
role and self-service disabled, plus `onboarding@example.test` with a required
first password change. It only targets a loopback managed demo. Their random
passwords are retained in an owner-readable `guide-accounts.json` inside the
disposable demo directory. Repeating the seeder retains existing account access
and passwords; it refuses unexpected identity settings. Set
`AAB_GUIDE_ACCOUNT_FILE` for an alternate handoff filename in that directory,
and pass the same value to the capture script. Initial demo reseeding removes
these identities and their handoff, so rerun the guide-account seeder afterward.

The guide includes populated drafts for creating users, groups, and service
accounts; selecting a new group member; editing resources and grants; entering
a masked service credential; supplying a repository for Git HTTP verification;
and reviewing a restricted agent token before issuance. Forms remain
unsubmitted. Jira verification success and failure images use browser-only
simulated responses, explicitly identified in the manifest. They demonstrate
the portal states without contacting an upstream or changing stored credentials.
It also includes local login, a required password-change draft, actual auditor
views, new grant/resource drafts, account access, and disable/revoke confirmations.
See the [illustrated portal guide](../docs/portal-guide/index.md) for the resulting
role-based walkthroughs.

Set `AAB_CAPTURE_STREAM=showcase` or `guide` to capture one stream. Optional
`AAB_DEMO_URL`, `AAB_CAPTURE_GRANT_ID`, and `AAB_CAPTURE_REQUEST_ID` choose the
running origin, grant drawer, and paired audit request. Refreshing one stream
preserves the other stream's manifest entries. Honor
`PLAYWRIGHT_BROWSERS_PATH` when Chromium is installed in a custom directory.
The script leaves token forms unsubmitted, captures no secrets or sign-in
state files, and rejects unexpected mutation requests. Review selected images
before placing them in `docs/images/portal/`; raw captures remain ignored under
`.scratch/` by default.

The published walkthroughs use annotated copies under
`docs/images/portal/guide-annotated/`, with orange highlights and callouts for
the current task. Preserve `guide/` originals when producing these overlays.
The capture script continues to write raw screenshots; annotations are a
separate documentation step and are reviewed before their guide links change.

The [capture inventory](../docs/images/portal/capture-manifest.json) records
themes, dimensions, descriptions, and original checksums for the published
guide images. Keep unselected captures and selection notes outside the product
repository.
