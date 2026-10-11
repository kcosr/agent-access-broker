#!/usr/bin/env node
// Add only documentation identities to the disposable loopback managed demo.
// Secrets stay in an owner-readable handoff file outside the repository.
import { randomBytes, randomUUID } from 'node:crypto';
import { lstat, readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';

const base = await realpath(process.env.AAB_DEMO_BASE ?? '/tmp/agent-access-broker-demo');
const temp = await realpath('/tmp');
if (path.dirname(base) !== temp || !/^agent-access-broker-demo(?:-[a-zA-Z0-9_-]+)?$/.test(path.basename(base))) {
  throw new Error('Guide identities may only be added to a disposable managed demo directory');
}
const filename = path.resolve(process.env.AAB_GUIDE_ACCOUNT_FILE ?? path.join(base, 'guide-accounts.json'));
if (await realpath(path.dirname(filename)) !== base) throw new Error('Keep the guide account file directly inside the disposable demo directory');
const origin = new URL(process.env.AAB_DEMO_URL ?? process.env.AGENT_ACCESS_URL ?? 'http://127.0.0.1:18787');
if (!['127.0.0.1', '[::1]', 'localhost'].includes(origin.hostname) || origin.protocol !== 'http:') throw new Error('Guide seeding requires the loopback HTTP demo');
if (!process.env.AAB_DEMO_ADMIN_PRINCIPAL || !process.env.AAB_DEMO_ADMIN_PASSWORD) throw new Error('Source the private demo credentials first');

let accounts;
try {
  const info = await lstat(filename);
  if (!info.isFile() || info.uid !== process.getuid() || info.mode & 0o077) throw new Error('Guide account file must be a regular owner-readable file belonging to the current user');
  accounts = JSON.parse(await readFile(filename, 'utf8'));
  if (accounts.origin !== origin.origin || accounts.auditor?.principal !== 'auditor@example.test' || accounts.onboarding?.principal !== 'onboarding@example.test') throw new Error('Guide account file does not match this demo');
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
  accounts = { origin: origin.origin,
    auditor: { principal: 'auditor@example.test', password: randomBytes(24).toString('base64url') },
    onboarding: { principal: 'onboarding@example.test', password: randomBytes(24).toString('base64url') },
  };
  await writeFile(filename, `${JSON.stringify(accounts, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
}

const login = await fetch(new URL('/v1/auth/local/login', origin), {
  method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin.origin },
  body: JSON.stringify({ principalId: process.env.AAB_DEMO_ADMIN_PRINCIPAL, password: process.env.AAB_DEMO_ADMIN_PASSWORD, returnTo: '/ui/admin/principals' }),
});
const envelope = await login.json();
if (!login.ok || !envelope.ok || envelope.result?.role !== 'admin' || envelope.result?.passwordChangeRequired) throw new Error('Guide seeding requires a ready administrator session');
const session = envelope.result;
const cookie = login.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
async function api(route, method = 'GET', body) {
  const response = await fetch(new URL(route, origin), {
    method, headers: { Cookie: cookie, Origin: origin.origin,
      'X-Agent-Access-Request-Id': `guide-seed-${randomUUID()}`,
      ...(body ? { 'Content-Type': 'application/json', [session.csrfHeader]: session.csrfToken } : {}),
    }, ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const result = await response.json();
  if (!response.ok || !result.ok) throw new Error(`Guide seed failed: ${method} ${route}, HTTP ${response.status} (${result.reasonCode ?? 'unknown'})`);
  return result.result;
}
const inventory = await api('/v1/admin/principals');
for (const persona of ['auditor', 'onboarding']) {
  const account = accounts[persona];
  const role = persona === 'auditor' ? 'auditor' : 'user';
  const selfServiceEnabled = persona !== 'auditor';
  let principal = inventory.find(value => value.principalId === account.principal);
  if (!principal) principal = await api('/v1/admin/principals', 'POST', {
    principalId: account.principal, displayName: persona === 'auditor' ? 'Documentation Auditor' : 'New Demo User', kind: 'user', role, selfServiceEnabled,
  });
  if (principal.role !== role || principal.selfServiceEnabled !== selfServiceEnabled || principal.status !== 'active') throw new Error(`Existing guide identity has unexpected access: ${account.principal}`);
  const route = `/v1/admin/principals/${encodeURIComponent(account.principal)}/login-methods`;
  const methods = await api(route);
  if (!methods.some(method => method.method === 'local_password' && method.status === 'active')) {
    await api(`${route}/local-password/enable`, 'POST', { password: account.password, mustChangePassword: persona === 'onboarding', acknowledgeSeparateSignIn: true });
  }
  console.log(`Ready ${persona} documentation identity: ${account.principal}`);
}
console.log(`Private guide credentials: ${filename}`);
