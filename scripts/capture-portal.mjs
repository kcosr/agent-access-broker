#!/usr/bin/env node
// Capture an already configured, synthetic demo. Never issue tokens or save forms.
// Guide verification outcomes are browser-only fixtures, labeled in the manifest.
// Install portal dependencies and Playwright Chromium before running this script.
// Required: AAB_DEMO_ALICE_PRINCIPAL/PASSWORD; the full section also requires
// AAB_DEMO_ADMIN_PRINCIPAL/PASSWORD.
// Optional: AAB_DEMO_URL, AAB_CAPTURE_OUTPUT, AAB_CAPTURE_STREAM (all/showcase/guide),
// AAB_CAPTURE_SECTION (all/tokens), AAB_CAPTURE_REQUEST_ID, AAB_CAPTURE_GRANT_ID,
// AAB_CAPTURE_AUDIT_SEARCH,
// AAB_GUIDE_ACCOUNT_FILE (private file from demo/seed-guide-accounts.mjs),
// AAB_CHROMIUM_EXECUTABLE_PATH. Captures default to ignored .scratch output;
// set AAB_CAPTURE_OUTPUT to an external review directory before selecting assets.
// PLAYWRIGHT_BROWSERS_PATH is respected by Playwright itself.
import { chromium, expect } from '../apps/portal/node_modules/@playwright/test/index.mjs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const origin = new URL(process.env.AAB_DEMO_URL ?? 'http://127.0.0.1:18787').origin;
const output = path.resolve(process.env.AAB_CAPTURE_OUTPUT ?? '.scratch/portal-captures');
const stream = process.env.AAB_CAPTURE_STREAM ?? 'all';
const section = process.env.AAB_CAPTURE_SECTION ?? 'all';
if (!['all', 'tokens'].includes(section)) throw new Error('AAB_CAPTURE_SECTION must be all or tokens');
if (!['all', 'showcase', 'guide'].includes(stream)) throw new Error('AAB_CAPTURE_STREAM must be all, showcase, or guide');
const grantId = process.env.AAB_CAPTURE_GRANT_ID ?? 'jira-demo-work';
const auditSearch = process.env.AAB_CAPTURE_AUDIT_SEARCH ?? 'demo-showcase';
const auditBase = `/ui/admin/audit?range=7d&q=${encodeURIComponent(auditSearch)}`;
const accounts = {
  alice: [process.env.AAB_DEMO_ALICE_PRINCIPAL, process.env.AAB_DEMO_ALICE_PASSWORD],
};
if (section === 'all') accounts.admin = [process.env.AAB_DEMO_ADMIN_PRINCIPAL, process.env.AAB_DEMO_ADMIN_PASSWORD];
if (section === 'all' && (stream === 'all' || stream === 'guide')) {
  const guideAccounts = JSON.parse(await readFile(process.env.AAB_GUIDE_ACCOUNT_FILE ?? '/tmp/agent-access-broker-demo/guide-accounts.json', 'utf8'));
  if (guideAccounts.origin !== origin) throw new Error('Guide account origin differs from the capture origin');
  for (const persona of ['auditor', 'onboarding']) accounts[persona] = [guideAccounts[persona]?.principal, guideAccounts[persona]?.password];
}
for (const [persona, credentials] of Object.entries(accounts)) {
  if (credentials.some(value => !value)) throw new Error(`Missing ${persona} demo credentials in environment`);
}
const manifest = [];
const browser = await chromium.launch({
  ...(process.env.AAB_CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.AAB_CHROMIUM_EXECUTABLE_PATH } : {}),
});

async function session(persona, theme, work) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 960 }, deviceScaleFactor: 1,
    colorScheme: theme, reducedMotion: 'reduce', locale: 'en-US', timezoneId: 'UTC',
  });
  await context.addInitScript(theme => localStorage.setItem('aab.portal.theme', theme), theme);
  const page = await context.newPage();
  page.setDefaultTimeout(20_000);
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  // The only writes allowed during a capture are sign-in and safe access previews.
  await page.route('**/v1/**', async route => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method()) ||
      (request.method() === 'POST' && (pathname === '/v1/auth/local/login' || pathname.endsWith('/effective-access')))) {
      await route.continue();
    } else {
      errors.push(`Blocked unexpected mutation: ${request.method()} ${pathname}`);
      await route.abort();
    }
  });
  try {
    await page.goto(`${origin}/ui`);
    if (persona === 'onboarding') await capture(page, 'guide', 'login-light', theme, 'Local browser sign-in before entering credentials; Microsoft login is not configured in this demo');
    await page.getByLabel('Principal', { exact: true }).fill(accounts[persona][0]);
    await page.getByLabel('Password', { exact: true }).fill(accounts[persona][1]);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.getByRole('button', { name: 'Account', exact: true }).waitFor();
    await ready(page);
    if (persona === 'auditor') {
      const response = await page.request.get(`${origin}/v1/auth/session`);
      const state = (await response.json()).result;
      if (state.role !== 'auditor' || state.selfServiceEnabled !== false) throw new Error('Auditor screenshots require an actual auditor session with self-service disabled');
    }
    await work(page);
    if (errors.length) throw new Error(`${persona}/${theme}: ${errors.join('; ')}`);
  } finally {
    await context.close();
  }
}

async function ready(page, allowDraftValidation = false) {
  await page.evaluate(() => document.fonts.ready);
  await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
  if (!allowDraftValidation) await expect(page.locator('[role="alert"]')).toHaveCount(0);
}

async function capture(page, destination, name, theme, description) {
  await ready(page);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await page.mouse.move(0, 0);
  const dir = path.join(output, destination);
  await mkdir(dir, { recursive: true });
  await page.screenshot({ path: path.join(dir, `${name}.png`), animations: 'disabled' });
  manifest.push({ file: `${destination}/${name}.png`, theme, viewport: '1440x960', description });
  console.log(`Captured ${destination}/${name}.png (${theme})`);
}

async function visit(page, route, endpoint, check, allowDraftValidation = false) {
  // Only accept requests started by this navigation; a prior page may still be
  // completing the same endpoint when sign-in redirects or a route changes.
  const started = new WeakSet();
  const track = request => started.add(request);
  page.on('request', track);
  const response = page.waitForResponse(response =>
    started.has(response.request()) && new URL(response.url()).pathname === endpoint && response.request().method() === 'GET');
  let loaded;
  try {
    await page.goto(`${origin}${route}`);
    loaded = await response;
  } finally {
    page.off('request', track);
  }
  const body = await loaded.json();
  if (!loaded.ok() || body.ok === false) throw new Error(`Cannot load ${endpoint}: HTTP ${loaded.status()}`);
  if (check && !check(body.result)) throw new Error(`Demo lacks required data for ${endpoint}`);
  await page.getByRole('main').waitFor();
  await ready(page, allowDraftValidation);
  return body.result;
}

async function audit(page, destination, theme, persona = 'admin') {
  const list = await visit(page, auditBase, '/v1/admin/audit/events', result => result.items?.length >= 8);
  await expect(page.getByRole('table', { name: 'Audit records', exact: true }).getByRole('rowheader').first()).toBeVisible();
  await capture(page, destination, `${persona}-audit-${theme}`, theme, `${persona} viewing synthetic audit history with mixed decisions and service actions`);
  let selected;
  const requestId = process.env.AAB_CAPTURE_REQUEST_ID;
  if (requestId) selected = list.items.find(record => record.brokerRequestId === requestId);
  else {
    const counts = new Map();
    for (const record of list.items) counts.set(record.brokerRequestId, (counts.get(record.brokerRequestId) ?? 0) + 1);
    selected = list.items.find(record => counts.get(record.brokerRequestId) >= 2);
  }
  if (!selected) throw new Error('Seed a multi-phase request in the last seven days or set AAB_CAPTURE_REQUEST_ID to a listed request');
  const detail = `${auditBase}&request=${encodeURIComponent(selected.brokerRequestId)}&record=${encodeURIComponent(selected.auditId)}`;
  const timeline = await visit(page, detail, `/v1/admin/audit/requests/${selected.brokerRequestId}`, result => result.items?.length >= 2);
  const drawer = page.getByRole('complementary').filter({ has: page.getByRole('tab', { name: 'Summary', exact: true }) });
  await expect(drawer.getByRole('heading', { name: 'Outcome', exact: true })).toBeVisible();
  await capture(page, destination, `${persona}-audit-detail-${theme}`, theme, `${persona} viewing a synthetic audit request outcome, identity, resource references, and correlation identifiers`);
  await drawer.getByRole('tab', { name: /^Timeline/ }).click();
  await expect(drawer.getByRole('list', { name: 'Request timeline', exact: true }).getByRole('listitem')).toHaveCount(timeline.items.length);
  await capture(page, destination, `${persona}-audit-timeline-${theme}`, theme, `${persona} viewing a correlated synthetic request timeline, from the initial phase through the final outcome`);
  if (theme === 'light') {
    const filtered = await visit(page, `${auditBase}&decision=deny`, '/v1/admin/audit/events', result => result.items?.length > 0 && result.items.every(record => record.decision === 'deny'));
    await expect(page.getByRole('table', { name: 'Audit records', exact: true }).getByRole('rowheader').getByRole('link')).toHaveCount(filtered.items.length);
    await capture(page, destination, `${persona}-audit-denied-light`, theme, `${persona} viewing synthetic rejected requests and reason codes`);
  }
}

async function grant(page, destination, theme) {
  await visit(page, '/ui/admin/policies', '/v1/admin/policy/grants');
  const preview = page.waitForResponse(response => new URL(response.url()).pathname === '/v1/admin/policy/effective-access');
  await page.getByRole('link', { name: grantId, exact: true }).click();
  const drawer = page.getByRole('complementary', { name: `Grant ${grantId}`, exact: true });
  await drawer.waitFor();
  const response = await preview;
  if (!response.ok() || !(await response.json()).result?.access?.length) throw new Error('Grant effective-access preview failed or contains no access');
  await capture(page, destination, `admin-grant-${theme}`, theme, 'Grant boundary and effective access for a service');
}

async function adminDialogs(page) {
  await visit(page, '/ui/admin/principals', '/v1/admin/principals');
  await page.getByRole('button', { name: 'Create user', exact: true }).click();
  let dialog = page.getByRole('dialog', { name: 'Create user', exact: true });
  await dialog.getByLabel('Principal ID', { exact: true }).fill('morgan@example.test');
  await dialog.getByLabel('Display name').fill('Morgan Demo User');
  await dialog.getByLabel('Email').fill('morgan@example.test');
  await dialog.getByRole('combobox', { name: /^Groups/ }).fill('jira-users');
  await page.getByRole('option', { name: /^jira-users - Jira Users/ }).click();
  await dialog.getByRole('combobox', { name: /^Groups/ }).press('Escape');
  await dialog.getByRole('checkbox', { name: 'Enable local password sign-in', exact: true }).check();
  await dialog.getByRole('checkbox', { name: 'I authorize local password sign-in for this user independently of Microsoft sign-in.', exact: true }).check();
  await capture(page, 'guide', 'admin-create-user-light', 'light', 'Draft user enrollment, group selection, independent local password sign-in, and self-service');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();

  await visit(page, '/ui/admin/principals?kind=groups', '/v1/admin/groups');
  await page.getByRole('button', { name: 'Create group', exact: true }).click();
  dialog = page.getByRole('dialog', { name: 'Create group', exact: true });
  await dialog.getByLabel('Group ID', { exact: true }).fill('project-readers');
  await dialog.getByLabel('Display name').fill('Project Readers');
  await dialog.getByLabel('Description').fill('People and workloads allowed to read the demo project.');
  await capture(page, 'guide', 'admin-create-group-light', 'light', 'Draft policy group with a stable identifier and human-readable purpose');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();

  await visit(page, '/ui/admin/principals?kind=service-accounts', '/v1/admin/principals');
  await page.getByRole('button', { name: 'Create service account', exact: true }).click();
  dialog = page.getByRole('dialog', { name: 'Create service account', exact: true });
  await dialog.getByLabel('Principal ID', { exact: true }).fill('project-reporter');
  await dialog.getByLabel('Display name').fill('Project Reporting Workload');
  await dialog.getByRole('combobox', { name: /^Groups/ }).fill('jira-users');
  await page.getByRole('option', { name: /^jira-users - Jira Users/ }).click();
  await dialog.getByRole('combobox', { name: /^Groups/ }).press('Escape');
  await capture(page, 'guide', 'admin-create-service-account-light', 'light', 'Draft noninteractive workload account using a policy group');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();

  await visit(page, '/ui/admin/groups/jira-users/members', '/v1/admin/groups/jira-users');
  const member = page.getByRole('combobox', { name: 'Principal to add', exact: true });
  await member.fill('bob');
  const candidate = page.getByRole('option', { name: /Bob Demo User/ });
  await expect(candidate).toBeVisible();
  await capture(page, 'guide', 'admin-group-member-picker-light', 'light', 'Search the Jira group member picker for Bob without adding membership');
  await candidate.click();
  await expect(page.getByRole('button', { name: 'Add member', exact: true })).toBeEnabled();
  await capture(page, 'guide', 'admin-group-add-member-light', 'light', 'Draft Jira group membership selection ready for administrator review');

  const resources = await visit(page, '/ui/admin/catalog/resources', '/v1/admin/policy/resources');
  const resource = resources.find(resource => resource.resourceType === 'jira_project');
  if (!resource) throw new Error('Seed a Jira project resource before capturing its editor');
  await visit(page, `/ui/admin/catalog/resources?item=${encodeURIComponent(resource.id)}`, '/v1/admin/policy/resources');
  await page.getByRole('complementary').filter({ has: page.getByRole('button', { name: 'Edit', exact: true }) }).getByRole('button', { name: 'Edit', exact: true }).click();
  const resourceEditor = page.getByRole('complementary', { name: /^Edit resource / });
  await expect(resourceEditor.getByLabel('Canonical identifier', { exact: true })).toHaveValue('DEMO');
  await capture(page, 'guide', 'admin-resource-editor-light', 'light', 'Jira typed resource editor with canonical identifier and execution contexts');
  await resourceEditor.getByRole('button', { name: 'Cancel', exact: true }).click();

  await visit(page, `/ui/admin/policies/${encodeURIComponent(grantId)}/edit`, '/v1/admin/policy/grants');
  await expect(page.getByRole('main', { name: 'Edit grant', exact: true })).toBeVisible();
  await capture(page, 'guide', 'admin-grant-editor-light', 'light', 'Grant editor with explicit subjects, service actions, credential mode, and execution contexts');
}

async function guideAdministration(page) {
  await visit(page, '/ui/admin/catalog/resources', '/v1/admin/policy/resources');
  await page.getByRole('button', { name: 'Add resource', exact: true }).first().click();
  const resource = page.getByRole('complementary', { name: 'Add resource', exact: true });
  await resource.getByLabel('Resource type', { exact: true }).selectOption('jira_project');
  await resource.getByLabel('Canonical identifier', { exact: true }).fill('DEMO');
  await resource.getByLabel('Display name').fill('Demo Jira Project');
  await resource.getByRole('group', { name: 'Allowed execution contexts', exact: true }).getByRole('checkbox', { name: 'default', exact: true }).check();
  await capture(page, 'guide', 'admin-create-resource-light', 'light', 'Unsaved Jira project resource draft for DEMO; reuse the existing demo entry rather than saving a duplicate');
  await resource.getByRole('button', { name: 'Cancel', exact: true }).click();

  await visit(page, '/ui/admin/policies/new', '/v1/admin/policy/grants', undefined, true);
  const subjects = page.locator('#grant-subjects');
  await subjects.getByRole('combobox', { name: 'Group', exact: true }).fill('jira-users');
  await page.getByRole('option', { name: /^Jira Users.*jira-users/ }).click();
  await page.getByLabel('Service', { exact: true }).selectOption('jira');
  await page.getByRole('checkbox', { name: 'issue.view', exact: true }).check();
  await page.getByRole('checkbox', { name: 'search', exact: true }).check();
  await page.getByLabel('Credential mode', { exact: true }).selectOption('per_user');
  await page.getByRole('group', { name: 'Execution contexts', exact: true }).getByRole('checkbox', { name: 'default', exact: true }).check();
  await page.getByRole('group', { name: 'Resources', exact: true }).getByRole('checkbox', { name: 'DEMO', exact: true }).check();
  await page.getByLabel('Grant ID').fill('jira-project-readers');
  await expect(page.getByRole('region', { name: 'Save grant', exact: true }).getByRole('button', { name: 'Create grant', exact: true })).toBeEnabled();
  await expect(page.getByRole('complementary', { name: 'Preview', exact: true })).toContainText('DEMO');
  await page.getByRole('complementary', { name: 'Grant sections', exact: true }).getByRole('button', { name: 'Subjects', exact: true }).click();
  // Sidebar jumps use smooth scrolling in the application. Position the same
  // section instantly before capture so a mid-scroll frame is never recorded.
  await page.locator('#grant-subjects').evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
  await capture(page, 'guide', 'admin-create-grant-light', 'light', 'Unsaved least-privilege Jira grant: Jira Users, issue.view/search, default, per_user, direct DEMO resource');
  await page.locator('#grant-service').evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
  await capture(page, 'guide', 'admin-grant-actions-light', 'light', 'Unsaved new Jira grant with only issue.view and search selected; no write-capable actions');
  await page.getByRole('complementary', { name: 'Grant sections', exact: true }).getByRole('button', { name: 'Resources', exact: true }).click();
  await page.locator('#grant-resources').evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
  await capture(page, 'guide', 'admin-grant-resources-light', 'light', 'Unsaved new grant resource selection and effective access for the DEMO Jira project');
  // Full navigation discards this unsaved draft; no save endpoint is called.
  await visit(page, `/ui/admin/principals/${encodeURIComponent(accounts.auditor[0])}`, `/v1/admin/principals/${encodeURIComponent(accounts.auditor[0])}`);
  await page.getByRole('heading', { name: 'Account access', exact: true }).scrollIntoViewIfNeeded();
  await expect(page.getByLabel('Role', { exact: true })).toHaveValue('auditor');
  await expect(page.getByRole('checkbox', { name: /Self-service enabled$/ })).not.toBeChecked();
  await capture(page, 'guide', 'admin-account-access-light', 'light', 'Administrator viewing a real documentation auditor role with personal self-service disabled');

  await visit(page, '/ui/admin/principals/bob%40example.test', '/v1/admin/principals/bob%40example.test');
  await page.getByRole('button', { name: 'Disable user', exact: true }).click();
  await page.getByRole('alertdialog', { name: 'Disable user?', exact: true }).waitFor();
  await capture(page, 'guide', 'admin-disable-user-light', 'light', 'User disable confirmation; dismissed without changing the account');
  await page.getByRole('alertdialog', { name: 'Disable user?', exact: true }).getByRole('button', { name: 'Cancel', exact: true }).click();
}

async function firstLoginGuide(page) {
  await expect(page.getByText('Change your password to continue', { exact: true })).toBeVisible();
  await page.getByLabel('Current password', { exact: true }).fill(accounts.onboarding[1]);
  const next = 'synthetic-documentation-password';
  await page.getByLabel('New password', { exact: true }).fill(next);
  await page.getByLabel('Confirm new password', { exact: true }).fill(next);
  await capture(page, 'guide', 'user-first-password-light', 'light', 'Actual temporary-password account with a required first change; masked draft is not submitted');
}

async function credentialGuide(page) {
  // Model provider responses at the browser boundary, as the portal e2e suite
  // does. No verification or secret write reaches the broker or an upstream.
  // Every resulting image is explicitly marked simulated in the manifest.
  let outcome = null;
  let record;
  const listPath = '/v1/credentials';
  const verifyPath = '/v1/credentials/connections/jira/verify';
  const checkedAt = new Date().toISOString();
  const simulated = () => ({ ...record,
    verificationStatus: outcome === 'success' ? 'upstream_verified' : 'verification_failed',
    // A failed recheck retains the previous successful verification timestamp.
    lastVerifiedAt: checkedAt,
    lastVerificationAttemptAt: checkedAt,
    lastVerificationErrorCode: outcome === 'success' ? null : 'upstream_unauthorized',
  });
  const fixture = async route => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'GET' && pathname === listPath) {
      const response = await route.fetch();
      const body = await response.json();
      record = body.result?.connections?.find(value => value.connection === 'jira')?.credential;
      if (!record) throw new Error('Credential test capture requires the seeded Jira credential');
      if (outcome) body.result.connections = body.result.connections.map(value => value.connection === 'jira' ? { ...value, credential: simulated() } : value);
      await route.fulfill({ response, json: body });
    } else if (request.method() === 'POST' && pathname === verifyPath && outcome) {
      await route.fulfill({ status: outcome === 'success' ? 200 : 424,
        json: outcome === 'success' ? { ok: true, result: simulated() }
          : { ok: false, reasonCode: 'upstream_unauthorized', error: { message: 'The upstream rejected this credential. Check the username and token, then verify again.' } },
      });
    } else await route.fallback();
  };
  await page.route('**/v1/credentials**', fixture);
  try {
    await visit(page, '/ui/credentials', listPath);
    const row = page.getByRole('row').filter({ has: page.getByRole('link', { name: 'Jira', exact: true }) });
    await row.getByRole('link').click();
    const drawer = page.getByRole('complementary', { name: 'Jira credential', exact: true });
    await drawer.getByLabel(/username/i).fill('alice@example.test');
    await drawer.getByLabel(/token/i).first().fill('demo-documentation-token');
    await expect(drawer.getByRole('button', { name: 'Replace credential', exact: true })).toBeEnabled();
    await capture(page, 'guide', 'user-credential-input-light', 'light', 'Jira credential entry with a synthetic username and masked token; replacement draft is not saved');
    // Discard input before testing the saved synthetic credential.
    await page.goto(`${origin}/ui/credentials?credential=jira`);
    await drawer.waitFor();
    outcome = 'success';
    await drawer.getByRole('button', { name: 'Verify', exact: true }).click();
    await expect(row.getByText('Upstream verified', { exact: true })).toBeVisible();
    await expect(page.getByRole('status').filter({ hasText: 'Credential verified' })).toBeVisible();
    await capture(page, 'guide', 'user-credential-test-success-light', 'light', 'SIMULATED upstream verification success using browser-only response fixtures; no credential verification reaches the broker');
    outcome = 'failure';
    await drawer.getByRole('button', { name: 'Verify', exact: true }).click();
    await expect(row.getByText('Verification failed', { exact: true })).toBeVisible();
    await expect(drawer.getByText('upstream_unauthorized', { exact: true })).toBeVisible();
    await expect(page.getByRole('status').filter({ hasText: 'The upstream rejected this credential.' })).toBeVisible();
    await capture(page, 'guide', 'user-credential-test-failure-light', 'light', 'SIMULATED upstream verification failure with status, error code, and recovery message; browser-only response fixtures');
  } finally {
    await page.unroute('**/v1/credentials**', fixture);
  }
  // Show the repository input that verifying the shared GitLab connection through Git HTTP requires.
  await visit(page, '/ui/credentials', listPath);
  await page.getByRole('row').filter({ has: page.getByRole('link', { name: 'GitLab', exact: true }) }).getByRole('link', { name: 'GitLab', exact: true }).click();
  const gitDrawer = page.getByRole('complementary', { name: 'GitLab credential', exact: true });
  await gitDrawer.getByLabel('Repository', { exact: true }).fill('demo/app');
  await capture(page, 'guide', 'user-credential-test-repository-light', 'light', 'Verifying the shared GitLab credential through the Git gateway requires a repository; populated draft without submitting verification');
}

async function tokenCreation(page, destination, theme) {
  await visit(page, '/ui/tokens', '/v1/tokens');
  if (destination === 'guide' && section === 'all') await capture(page, destination, 'user-tokens-light', theme, 'User invocation token inventory and lifecycle status');
  await page.getByRole('button', { name: 'Issue token', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Issue agent token', exact: true })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('demo-jira-reader');
  await page.getByRole('group', { name: 'Access', exact: true }).getByRole('button', { name: 'Restrict to selected', exact: true }).click();
  await capture(page, destination, `user-token-details-${theme}`, theme, 'Synthetic unsubmitted token creation page with explicit lifetime, contexts, and restricted access');
  await page.getByRole('checkbox', { name: 'jira', exact: true }).check();
  const jira = page.getByRole('group', { name: 'jira token access', exact: true });
  await jira.getByRole('checkbox', { name: 'issue.view', exact: true }).check();
  await jira.evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
  await expect(jira.getByRole('group', { name: 'Read-only', exact: true })).toBeVisible();
  await expect(jira.getByRole('group', { name: 'Write-capable', exact: true })).toBeVisible();
  await capture(page, destination, `user-token-access-${theme}`, theme, 'Synthetic unsubmitted token restricted to Jira issue.view using the shared read-only and write-capable action columns');
  if (destination === 'guide') {
    await page.getByRole('group', { name: 'jira resources', exact: true }).getByRole('button', { name: 'Selected resources and groups', exact: true }).click();
    await page.locator('.wb-check').filter({ hasText: 'Jira project' }).getByRole('checkbox', { name: 'DEMO', exact: true }).check();
    await page.getByRole('group', { name: 'Resources and resource groups', exact: true }).evaluate(element => element.scrollIntoView({ block: 'center', behavior: 'instant' }));
    await capture(page, destination, 'user-token-resources-light', theme, 'Synthetic unsubmitted Jira token selecting only the exact DEMO Jira project resource');
    await page.getByRole('heading', { name: 'Issue agent token', exact: true }).evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
    await capture(page, destination, 'user-token-boundary-light', theme, 'Synthetic unsubmitted token page with the live summary rail and Effective access preview; no token is issued');
  }
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  const discard = page.getByRole('alertdialog', { name: 'Discard changes?', exact: true });
  await discard.getByRole('button', { name: 'Discard changes', exact: true }).click();
  await expect(page).toHaveURL(`${origin}/ui/tokens`);
}

async function selfService(page, destination, theme) {
  await visit(page, '/ui/access', '/v1/tokens/options', result => result.services?.length >= 2);
  await expect(page.getByRole('table', { name: 'Access', exact: true }).getByRole('rowheader').first()).toBeVisible();
  await capture(page, destination, `user-access-${theme}`, theme, 'User self-service access across available services and execution contexts');
  if (destination === 'guide') {
    await visit(page, '/ui/credentials', '/v1/credentials');
    await capture(page, destination, 'user-credentials-light', theme, 'User credential inventory without exposing credential values');
    await credentialGuide(page);
  }
  await tokenCreation(page, destination, theme);
  if (destination === 'guide') {
    await page.getByRole('button', { name: 'Revoke demo-agent-token', exact: true }).click();
    const revoke = page.getByRole('alertdialog', { name: 'Revoke token?', exact: true });
    await revoke.waitFor();
    await capture(page, 'guide', 'user-token-revoke-light', theme, 'Token revocation confirmation; dismissed without revoking the seeded token');
    await revoke.getByRole('button', { name: 'Cancel', exact: true }).click();
    await visit(page, '/ui/activity?range=7d', '/v1/audit/events', result => result.items?.length > 0);
    await capture(page, destination, 'user-activity-light', theme, 'Personal activity history limited to the signed-in user');
  }
}

try {
  if (section === 'tokens') {
    if (stream === 'all' || stream === 'showcase') {
      await session('alice', 'light', page => tokenCreation(page, 'showcase', 'light'));
      await session('alice', 'dark', page => tokenCreation(page, 'showcase', 'dark'));
    }
    if (stream === 'all' || stream === 'guide') await session('alice', 'light', page => tokenCreation(page, 'guide', 'light'));
  } else if (stream === 'all' || stream === 'showcase') {
    await session('admin', 'light', async page => {
      await audit(page, 'showcase', 'light');
      await grant(page, 'showcase', 'light');
    });
    await session('admin', 'dark', async page => {
      await audit(page, 'showcase', 'dark');
      await grant(page, 'showcase', 'dark');
    });
    await session('alice', 'light', page => selfService(page, 'showcase', 'light'));
    await session('alice', 'dark', page => selfService(page, 'showcase', 'dark'));
  }
  if (section === 'all' && (stream === 'all' || stream === 'guide')) {
    await session('onboarding', 'light', firstLoginGuide);
    await session('admin', 'light', async page => {
      await visit(page, '/ui/admin/principals', '/v1/admin/principals');
      await capture(page, 'guide', 'admin-principals-light', 'light', 'Configured demo principals and account roles');
      await adminDialogs(page);
      await guideAdministration(page);
      await visit(page, '/ui/admin/catalog/resources', '/v1/admin/policy/resources');
      await capture(page, 'guide', 'admin-resources-light', 'light', 'Typed resources available for grants');
      await grant(page, 'guide', 'light');
      await audit(page, 'guide', 'light');
    });
    await session('auditor', 'light', page => audit(page, 'guide', 'light', 'auditor'));
    await session('alice', 'light', page => selfService(page, 'guide', 'light'));
  }
  // A partial refresh retains unrelated captures. Token-page captures replace
  // the obsolete review-step image as well as the corresponding current images.
  let retained = [];
  if (stream !== 'all' || section !== 'all') {
    try {
      retained = JSON.parse(await readFile(path.join(output, 'manifest.json'), 'utf8')).captures
        .filter(entry => {
          if (stream !== 'all' && !entry.file.startsWith(`${stream}/`)) return true;
          if (section === 'all') return false;
          return !/^\w+\/user-token-(?:details|access|resources|review|boundary)-(?:light|dark)\.png$/.test(entry.file);
        });
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  await writeFile(path.join(output, 'manifest.json'), `${JSON.stringify({ captures: [...retained, ...manifest] }, null, 2)}\n`);
  console.log(`Saved ${manifest.length} screenshots to ${output}`);
} finally {
  await browser.close();
}
