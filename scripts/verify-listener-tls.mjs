#!/usr/bin/env node

// Executable acceptance, deliberately outside Cargo tests: HTTP/2 must work in
// the supplied normal production-feature Broker build. All keys, credentials,
// databases, sockets and processes belong to this run and are removed on exit.
import { spawn, execFileSync } from "node:child_process";
import { createHash, randomBytes, randomUUID, X509Certificate } from "node:crypto";
import { once } from "node:events";
import { constants, createReadStream, promises as fs } from "node:fs";
import http from "node:http";
import http2 from "node:http2";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import tls from "node:tls";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const HOST = "broker.example.test";
const GATEWAY_HOST = "git.example.test";
const REQUEST_TIMEOUT = 8_000;
const START_TIMEOUT = 30_000;
const HANDSHAKE_TIMEOUT = 5_000;
const HANDSHAKE_CAPACITY = 64;
const REQUEST_ID = "X-Agent-Access-Request-Id";
const children = new Set();
const sockets = new Set();
const sessions = new Set();
const privateValues = new Set();
const cases = [];
let interrupted = false;
let temporary;
let upstream;
let options;
let report;

function check(condition, message) {
  if (!condition) throw new Error(message);
}

function secret(value) {
  privateValues.add(value);
  return value;
}

function sanitized(value) {
  let text = String(value);
  for (const privateValue of privateValues) text = text.replaceAll(privateValue, "<redacted>");
  return text.replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, "<redacted private key>");
}

function argumentsOf(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--help" || argument === "-h") return { help: true };
    check(["--broker", "--output-dir"].includes(argument), `Unknown argument: ${argument}`);
    check(!parsed[argument] && args[index + 1] && !args[index + 1].startsWith("--"), `Supply ${argument} once with a value`);
    parsed[argument] = resolve(args[++index]);
  }
  check(parsed["--broker"], "--broker must name a freshly built Broker executable");
  return { broker: parsed["--broker"], output: parsed["--output-dir"] };
}

async function bounded(promise, milliseconds, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function until(predicate, label, milliseconds = REQUEST_TIMEOUT) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    check(!interrupted, "Verification interrupted");
    const result = await predicate();
    if (result) return result;
    await delay(30);
  }
  throw new Error(`${label} timed out`);
}

async function test(name, operation) {
  const started = Date.now();
  try {
    await operation();
    cases.push({ name, status: "passed", elapsedMs: Date.now() - started });
    console.log(`ok ${name} (${Date.now() - started} ms)`);
  } catch (error) {
    cases.push({ name, status: "failed", elapsedMs: Date.now() - started, error: sanitized(error.message) });
    throw error;
  }
}

async function writePrivate(path, data) {
  await fs.writeFile(path, data, { mode: 0o600 });
  await fs.chmod(path, 0o600);
}

async function replacePrivate(path, data) {
  const next = `${path}.next`;
  await writePrivate(next, data);
  await fs.rename(next, path);
}

function openssl(args) {
  try {
    return execFileSync("openssl", args, { cwd: temporary, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 });
  } catch {
    throw new Error("OpenSSL could not generate the isolated test certificate material");
  }
}

async function certificates() {
  const directory = join(temporary, "certificates");
  await fs.mkdir(directory, { mode: 0o700 });
  const caKey = join(directory, "ca.key");
  const caPath = join(directory, "ca.pem");
  openssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
    "-keyout", caKey, "-out", caPath, "-days", "2", "-subj", "/CN=Broker Listener Test CA",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  secret(await fs.readFile(caKey, "utf8"));
  const ca = await fs.readFile(caPath);
  const extensionPath = join(directory, "leaf.ext");
  await writePrivate(extensionPath, `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${HOST},DNS:${GATEWAY_HOST},DNS:localhost,IP:127.0.0.1\n`);
  const identities = [];
  for (let index = 0; index < 6; index += 1) {
    const keyPath = join(directory, `leaf-${index}.key`);
    const requestPath = join(directory, `leaf-${index}.csr`);
    const certPath = join(directory, `leaf-${index}.pem`);
    openssl(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
      "-keyout", keyPath, "-out", requestPath, "-subj", `/CN=Listener Test ${index}`]);
    openssl(["x509", "-req", "-in", requestPath, "-CA", caPath, "-CAkey", caKey,
      "-set_serial", String(index + 1), "-days", "2", "-extfile", extensionPath, "-out", certPath]);
    const cert = await fs.readFile(certPath, "utf8");
    const key = secret(await fs.readFile(keyPath, "utf8"));
    identities.push({ cert: `${cert}${ca.toString()}`, key, fingerprint: new X509Certificate(cert).fingerprint256 });
  }
  return { ca, caPath, identities };
}

function trackSocket(socket) {
  sockets.add(socket);
  socket.on("error", () => {});
  socket.once("close", () => sockets.delete(socket));
  return socket;
}

async function tcp(port) {
  const socket = trackSocket(net.connect({ host: "127.0.0.1", port }));
  socket.resume();
  try {
    await bounded(once(socket, "connect"), REQUEST_TIMEOUT, "TCP connection");
    return socket;
  } catch (error) {
    socket.destroy();
    throw error;
  }
}

async function tlsSocket(endpoint, extra = {}) {
  const socket = trackSocket(tls.connect({ host: "127.0.0.1", port: endpoint.port,
    servername: endpoint.host, ca: endpoint.ca, rejectUnauthorized: true,
    ALPNProtocols: ["http/1.1"], ...extra }));
  try {
    await bounded(once(socket, "secureConnect"), REQUEST_TIMEOUT, "TLS handshake");
    check(socket.authorized, "TLS connection must verify the certificate and hostname");
    return socket;
  } catch (error) {
    socket.destroy();
    throw error;
  }
}

async function fingerprint(endpoint) {
  const socket = await tlsSocket(endpoint);
  try { return socket.getPeerCertificate().fingerprint256; }
  finally { socket.destroy(); }
}

function request(endpoint, path, { method = "GET", headers = {}, body, agent, ...transport } = {}) {
  const data = body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body);
  return new Promise((resolveRequest, reject) => {
    const client = endpoint.secure ? https : http;
    const requestHeaders = { Host: endpoint.host, [REQUEST_ID]: randomUUID(), ...headers };
    if (data !== undefined) {
      requestHeaders["Content-Type"] ??= "application/json";
      requestHeaders["Content-Length"] = Buffer.byteLength(data);
    }
    const outgoing = client.request({ host: "127.0.0.1", port: endpoint.port, path, method,
      servername: endpoint.host, ca: endpoint.ca, rejectUnauthorized: true,
      ALPNProtocols: ["http/1.1"], agent: agent ?? false, headers: requestHeaders, ...transport }, (response) => {
      const chunks = [];
      let bytes = 0;
      response.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > 2 * 1024 * 1024) outgoing.destroy(new Error("Fixture response exceeded its byte limit"));
        else chunks.push(chunk);
      });
      response.once("error", reject);
      response.once("end", () => resolveRequest({ status: response.statusCode, headers: response.headers,
        body: Buffer.concat(chunks).toString(), version: response.httpVersion,
        alpn: response.socket?.alpnProtocol, reusedSocket: outgoing.reusedSocket }));
    });
    outgoing.once("error", reject);
    outgoing.setTimeout(REQUEST_TIMEOUT, () => outgoing.destroy(new Error("HTTP request timed out")));
    outgoing.end(data);
  });
}

function json(response) {
  try { return JSON.parse(response.body); }
  catch { throw new Error(`Expected JSON response (HTTP ${response.status})`); }
}

async function connectH2(endpoint) {
  const session = http2.connect(`https://${endpoint.host}:${endpoint.port}`, {
    createConnection: () => trackSocket(tls.connect({ host: "127.0.0.1", port: endpoint.port,
      servername: endpoint.host, ca: endpoint.ca, rejectUnauthorized: true, ALPNProtocols: ["h2"] })),
  });
  sessions.add(session);
  session.on("error", () => {});
  session.once("close", () => sessions.delete(session));
  try {
    await bounded(once(session, "connect"), REQUEST_TIMEOUT, "HTTP/2 connection");
    check(session.alpnProtocol === "h2", "Production executable must negotiate h2");
    return session;
  } catch (error) {
    session.destroy();
    throw error;
  }
}

async function h2Request(session, endpoint, path, { method = "GET", headers = {}, body } = {}) {
  const data = body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body);
  const stream = session.request({ ":method": method, ":path": path, ":authority": endpoint.host,
    [REQUEST_ID.toLowerCase()]: randomUUID(), ...(data === undefined ? {} : { "content-type": "application/json" }), ...headers });
  const result = new Promise((resolveRequest, reject) => {
    let responseHeaders;
    const chunks = [];
    let bytes = 0;
    stream.on("response", (value) => { responseHeaders = value; });
    stream.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > 2 * 1024 * 1024) stream.destroy(new Error("HTTP/2 fixture response exceeded its byte limit"));
      else chunks.push(chunk);
    });
    stream.once("error", reject);
    stream.once("end", () => resolveRequest({ status: responseHeaders?.[":status"], headers: responseHeaders,
      body: Buffer.concat(chunks).toString(), version: "2.0" }));
  });
  stream.end(data);
  try { return await bounded(result, REQUEST_TIMEOUT, "HTTP/2 request"); }
  finally { if (!stream.closed) stream.close(); }
}

function baseConfig(directory, upstreamPort, caPath, initialPassword) {
  return `[deployment]\nenvironment = "test"\nnode_id = "listener-test"\nenable_fake_service = true
[identity]
mode = "required"
authority = "managed"
[[identity.sources]]
name = "fixture"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"
[managed_store]
type = "sqlite"
path = ${JSON.stringify(join(directory, "store.sqlite"))}
auto_migrate = true
[credential_encryption]
active_key = "k1"
[[credential_encryption.keys]]
id = "k1"
provider = "env"
env = "AAB_LISTENER_TEST_ENCRYPTION"
[broker_tokens]
hash_key_ref = "env:AAB_LISTENER_TEST_HASH"
[browser_auth]
enabled = true
public_origin = "https://${HOST}"
csrf_key_ref = "env:AAB_LISTENER_TEST_CSRF"
[browser_auth.local_password]
enabled = true
pepper_ref = "env:AAB_LISTENER_TEST_PEPPER"
[management]
enabled = true
[management.initial_admin]
mode = "create_if_empty"
principal_id = "listener-test-admin"
initial_password = ${JSON.stringify(initialPassword)}
[policy]
authority = "toml"
default_decision = "deny"
[[policy.resources]]
id = "fixture-project"
resource_type = "fake_project"
selector = { kind = "exact", value = "TEST" }
allowed_execution_contexts = ["default"]
enabled = true
[[policy.resources]]
id = "fixture-repository"
resource_type = "git_repository"
selector = { kind = "exact", value = "fixture/repository" }
allowed_execution_contexts = ["default"]
enabled = true
[[policy.grants]]
subjects = ["user:listener-test-admin"]
service = "fake"
actions = ["echo"]
resources = { resource_ids = ["fixture-project"] }
credential_mode = "service"
[[policy.grants]]
subjects = ["user:listener-test-admin"]
service = "fixture_git"
actions = ["repo.fetch"]
resources = { resource_ids = ["fixture-repository"] }
credential_mode = "service"
[providers.fake]
[credentials.service.fixture_git]
type = "bearer_token"
token_ref = "env:AAB_LISTENER_TEST_UPSTREAM_TOKEN"
[gateways.fixture_git]
kind = "git_http"
display_name = "Fixture Git"
broker_hosts = ["${GATEWAY_HOST}"]
upstream_base_url = "https://127.0.0.1:${upstreamPort}"
allowed_upstream_hosts = ["https://127.0.0.1:${upstreamPort}/**"]
auth_modes = ["basic_broker_token"]
credential_modes = ["service"]
[gateways.fixture_git.git]
allow_fetch = true
allow_push = false
[network.outbound_tls]
trust = "custom"
ca_certificate = ${JSON.stringify(caPath)}
[mcp]
enabled = true
public_url = "https://${HOST}/mcp"
[limits]
upload_spool_dir = ${JSON.stringify(join(directory, "spool"))}
[audit]
type = "jsonl"
path = ${JSON.stringify(join(directory, "audit.jsonl"))}
`;
}

async function fixture(material, { publicTls = false, gatewayTls = false, gateway = true, browser = false } = {}) {
  const directory = await fs.mkdtemp(join(temporary, "instance-"));
  const token = secret(`listener-${randomUUID()}`);
  const keyNames = ["encryption", "hash", "csrf", "pepper"];
  const environment = { ...process.env, AAB_LISTENER_TEST_TOKEN: token,
    AAB_LISTENER_TEST_UPSTREAM_TOKEN: upstream.token,
    RUST_LOG: "agent_access_broker_host=info,agent_access_core=warn" };
  for (const name of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "AGENT_ACCESS_BROKER_CONFIG"]) delete environment[name];
  for (const name of keyNames) environment[`AAB_LISTENER_TEST_${name.toUpperCase()}`] = secret(randomBytes(32).toString("base64url"));
  const publicFiles = { cert: join(directory, "public.pem"), key: join(directory, "public.key") };
  const gatewayFiles = { cert: join(directory, "gateway.pem"), key: join(directory, "gateway.key") };
  await writePrivate(publicFiles.cert, material.identities[0].cert);
  await writePrivate(publicFiles.key, material.identities[0].key);
  await writePrivate(gatewayFiles.cert, material.identities[1].cert);
  await writePrivate(gatewayFiles.key, material.identities[1].key);
  const configPath = join(directory, "broker.toml");
  const initialPassword = secret(`fixture-initial-${randomBytes(18).toString("hex")}`);
  let config = baseConfig(directory, upstream.port, material.caPath, initialPassword);
  if (browser) {
    const portal = join(directory, "portal");
    await fs.mkdir(portal, { mode: 0o700 });
    await writePrivate(join(portal, "index.html"), "<!doctype html><title>Listener fixture</title><main>Native TLS fixture</main>");
    config = `[deployment]\nenvironment = "test"\nnode_id = "listener-browser-test"
[identity]
mode = "required"
authority = "managed"
[[identity.sources]]
name = "managed"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"
[managed_store]
type = "sqlite"
path = ${JSON.stringify(join(directory, "store.sqlite"))}
auto_migrate = true
[credential_encryption]
active_key = "k1"
[[credential_encryption.keys]]
id = "k1"
provider = "env"
env = "AAB_LISTENER_TEST_ENCRYPTION"
[broker_tokens]
hash_key_ref = "env:AAB_LISTENER_TEST_HASH"
[browser_auth]
enabled = true
public_origin = "https://${HOST}"
csrf_key_ref = "env:AAB_LISTENER_TEST_CSRF"
[browser_auth.local_password]
enabled = true
pepper_ref = "env:AAB_LISTENER_TEST_PEPPER"
[management]
enabled = true
[management.initial_admin]
mode = "create_if_empty"
principal_id = "admin"
initial_password = ${JSON.stringify(initialPassword)}
[portal]
enabled = true
static_dir = ${JSON.stringify(portal)}
[policy]
authority = "managed"
default_decision = "deny"
[limits]
upload_spool_dir = ${JSON.stringify(join(directory, "spool"))}
[audit]
type = "jsonl"
path = ${JSON.stringify(join(directory, "audit.jsonl"))}
`;
  }
  await writePrivate(configPath, config);
  const args = ["--config", configPath, "serve", "--listen", "127.0.0.1:0", "--shutdown-timeout-ms", "600"];
  if (publicTls) args.push("--tls-cert-chain", publicFiles.cert, "--tls-private-key", publicFiles.key);
  if (gateway) args.push("--gateway-listen", "127.0.0.1:0");
  if (gatewayTls) args.push("--gateway-tls-cert-chain", gatewayFiles.cert, "--gateway-tls-private-key", gatewayFiles.key);
  return { directory, configPath, config, token, initialPassword, environment, args, publicFiles, gatewayFiles,
    publicTls, gatewayTls, gateway, browser, ca: material.ca };
}

function launch(fixture, extraArgs = []) {
  const child = spawn(options.broker, [...fixture.args, ...extraArgs], { cwd: REPO, env: fixture.environment, stdio: ["ignore", "pipe", "pipe"] });
  const processState = { child, fixture, exited: false, result: undefined, log: "", events: [], output: "" };
  children.add(processState);
  let partial = "";
  child.stdout.on("data", (chunk) => { processState.output = (processState.output + chunk.toString()).slice(-64 * 1024); });
  child.stderr.on("data", (chunk) => {
    processState.log = (processState.log + chunk.toString()).slice(-128 * 1024);
    partial += chunk.toString();
    for (;;) {
      const newline = partial.indexOf("\n");
      if (newline < 0) break;
      const line = partial.slice(0, newline);
      partial = partial.slice(newline + 1);
      try { processState.events.push(JSON.parse(line)); } catch { /* Startup diagnostics need not be JSON. */ }
    }
  });
  processState.closed = new Promise((resolveClosed) => {
    child.once("error", (error) => { processState.spawnError = error.code ?? "spawn_failed"; });
    child.once("close", (code, signal) => {
      processState.exited = true;
      processState.result = { code, signal };
      resolveClosed(processState.result);
    });
  });
  return processState;
}

async function start(fixture) {
  try {
    execFileSync(options.broker, ["--config", fixture.configPath, "config", "validate"], {
      cwd: REPO, env: fixture.environment, stdio: ["ignore", "pipe", "pipe"], timeout: START_TIMEOUT,
    });
  } catch (error) {
    throw new Error(`Fixture configuration rejected: ${sanitized(error.stderr?.toString() ?? "validation failed").trim()}`);
  }
  const running = launch(fixture);
  await until(() => {
    check(!running.exited, `Broker exited during startup (${running.result?.code ?? running.spawnError})`);
    const listeners = running.events.filter((event) => event.event === "broker_listening");
    return listeners.some((event) => event.listener === "public")
      && (!fixture.gateway || listeners.some((event) => event.listener === "gateway"));
  }, "Broker listener startup", START_TIMEOUT);
  for (const [name, host, secure] of [["public", HOST, fixture.publicTls], ["gateway", GATEWAY_HOST, fixture.gatewayTls]]) {
    if (name === "gateway" && !fixture.gateway) continue;
    const event = running.events.find((item) => item.event === "broker_listening" && item.listener === name);
    check(/^127\.0\.0\.1:\d+$/.test(event.address), "Fixture must bind a loopback address");
    running[name] = { host, port: Number(event.address.split(":").at(-1)), secure, ca: fixture.ca };
  }
  check((await request(running.public, "/v1/readyz")).status === 200, "Broker fixture must be ready");
  if (!fixture.browser) await bootstrap(running);
  return running;
}

async function bootstrap(running) {
  const origin = `https://${HOST}`;
  const login = await request(running.public, "/v1/auth/local/login", { method: "POST", headers: { Origin: origin },
    body: { principalId: "listener-test-admin", password: running.fixture.initialPassword, returnTo: "/ui" } });
  check(login.status === 200, "Fixture administrator login must succeed");
  const initialCookie = secret(login.headers["set-cookie"][0].split(";")[0]);
  const initialCsrf = secret(json(login).result.csrfToken);
  const password = secret(`listener-updated-${randomBytes(18).toString("hex")}`);
  const changed = await request(running.public, "/v1/auth/local/password/change", { method: "POST",
    headers: { Origin: origin, Cookie: initialCookie, "X-Agent-Access-CSRF": initialCsrf },
    body: { currentPassword: running.fixture.initialPassword, newPassword: password } });
  check(changed.status === 200, "Fixture administrator password setup must succeed");
  const cookie = secret(changed.headers["set-cookie"][0].split(";")[0]);
  const csrf = secret(json(changed).result.csrfToken);
  for (const tokenClass of ["admin", "agent_invoke"]) {
    const response = await request(running.public, "/v1/admin/principals/listener-test-admin/tokens", { method: "POST",
      headers: { Origin: origin, Cookie: cookie, "X-Agent-Access-CSRF": csrf },
      body: { name: "listener-acceptance", tokenClass, ttl: tokenClass === "admin" ? "2h" : "8h",
        ...(tokenClass === "agent_invoke" ? { scopes: { readOnly: true, allowedExecutionContexts: ["default"] } } : {}) } });
    check(response.status === 200, `Fixture ${tokenClass} token issuance must succeed (HTTP ${response.status}, reason ${json(response).reasonCode ?? "none"})`);
    const token = secret(json(response).result.token);
    if (tokenClass === "admin") running.fixture.adminToken = token;
    else running.fixture.token = token;
  }
}

async function stop(running, requireGraceful = true) {
  if (!running.exited) running.child.kill("SIGTERM");
  try {
    const result = await bounded(running.closed, 5_000, "Broker shutdown");
    if (requireGraceful) check(result.code === 0 && result.signal === null, "Broker must finish shutdown without external termination");
  } catch (error) {
    if (!running.exited) running.child.kill("SIGKILL");
    await running.closed;
    throw error;
  }
}

function auth(running) {
  return { Authorization: `Bearer ${running.fixture.adminToken}` };
}

function invocationAuth(running) {
  return { Authorization: `Bearer ${running.fixture.token}` };
}

async function status(running) {
  const response = await request(running.public, "/v1/admin/config/status", { headers: auth(running) });
  check(response.status === 200, "Admin config status must succeed");
  return json(response).result;
}

async function auditFor(running, requestId) {
  return until(async () => {
    const contents = await fs.readFile(join(running.fixture.directory, "audit.jsonl"), "utf8");
    for (const line of contents.split("\n")) {
      try {
        const record = JSON.parse(line);
        if (record.agentRequestId === requestId) return record;
      } catch { /* The writer may still be finishing the last line. */ }
    }
    return null;
  }, "Invocation audit record");
}

async function reload(running, successful) {
  const response = await request(running.public, "/v1/admin/config/reload", { method: "POST", headers: auth(running) });
  check(successful ? response.status === 200 : response.status >= 400, successful ? "Admin reload must succeed" : "Invalid reload must be rejected");
  return json(response);
}

async function replaceIdentity(files, identity) {
  await replacePrivate(files.cert, identity.cert);
  await replacePrivate(files.key, identity.key);
}

function mcpMessage(response) {
  if (response.headers["content-type"]?.includes("text/event-stream")) {
    const messages = response.body.split(/\r?\n/).filter((line) => line.startsWith("data:")).map((line) => JSON.parse(line.slice(5).trim()));
    const message = messages.find((value) => value.id !== undefined);
    check(message, "MCP SSE response must contain a JSON-RPC result");
    return message;
  }
  return json(response);
}

async function mcpExchange(running, send = (path, init) => request(running.public, path, init)) {
  let headers = { ...invocationAuth(running), Accept: "application/json, text/event-stream" };
  const initialized = await send("/mcp", { method: "POST", headers, body: {
    jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "listener-acceptance", version: "1" } },
  } });
  check(initialized.status === 200 && mcpMessage(initialized).result?.protocolVersion === "2025-11-25", "MCP initialization must succeed");
  const session = initialized.headers["mcp-session-id"];
  check(typeof session === "string", "MCP initialization must create a session");
  headers = { ...headers, "Mcp-Session-Id": session, "MCP-Protocol-Version": "2025-11-25" };
  const notification = await send("/mcp", { method: "POST", headers, body: { jsonrpc: "2.0", method: "notifications/initialized" } });
  check(notification.status === 202, "MCP initialized notification must succeed");
  const response = await send("/mcp", { method: "POST", headers, body: {
    jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "fake_echo", arguments: { inputs: { project: "TEST", message: "listener transport" } } },
  } });
  const result = mcpMessage(response).result;
  check(response.status === 200 && result && !result.isError && JSON.stringify(result).includes("listener transport"), "MCP invocation must use the Broker router and policy");
  const closed = await send("/mcp", { method: "DELETE", headers });
  check(closed.status === 202, "MCP session cleanup must succeed");
}

const GIT_PATH = "/fixture/repository.git/info/refs?service=git-upload-pack";
const GIT_BODY = "001e# service=git-upload-pack\n00000000";

async function startUpstream(material) {
  const token = secret(`upstream-${randomUUID()}`);
  const state = { token, requests: 0, streaming: false, streams: new Set() };
  const server = https.createServer({ key: material.identities[0].key, cert: material.identities[0].cert }, (incoming, response) => {
    if (incoming.url !== GIT_PATH || incoming.headers.authorization !== `Bearer ${token}`) {
      response.writeHead(403).end();
      return;
    }
    state.requests += 1;
    response.writeHead(200, { "content-type": "application/x-git-upload-pack-advertisement" });
    if (state.streaming) {
      state.streams.add(response);
      response.on("close", () => state.streams.delete(response));
      response.write(GIT_BODY);
    } else response.end(GIT_BODY);
  });
  server.on("connection", trackSocket);
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  return { ...state, get requests() { return state.requests; }, get streams() { return state.streams; },
    set streaming(value) { state.streaming = value; }, port: server.address().port,
    close: async () => { server.closeAllConnections(); await new Promise((done) => server.close(done)); } };
}

function gatewayAuth(running) {
  return { Authorization: `Basic ${Buffer.from(`agent-access:${running.fixture.token}`).toString("base64")}` };
}

async function listenerModes(material) {
  for (const [publicTls, gatewayTls] of [[false, false], [true, false], [false, true], [true, true]]) {
    const name = `public ${publicTls ? "HTTPS" : "HTTP"}, gateway ${gatewayTls ? "HTTPS" : "HTTP"}`;
    await test(name, async () => {
      const running = await start(await fixture(material, { publicTls, gatewayTls }));
      try {
        const health = await request(running.public, "/v1/healthz");
        check(health.status === 200 && health.version === "1.1", "Public listener must serve HTTP/1.1 health");
        const echoId = randomUUID();
        const echo = await request(running.public, "/v1/invoke/fake/echo", { method: "POST",
          headers: { ...invocationAuth(running), [REQUEST_ID]: echoId, "X-Forwarded-For": "198.51.100.7" },
          body: { inputs: { project: "TEST", message: "listener transport" } } });
        check(echo.status === 200 && json(echo).result?.message === "listener transport", "Public listener must invoke the configured service");
        const audit = await auditFor(running, echoId);
        check(/^127\.0\.0\.1:\d+$/.test(audit.source?.remote) && !audit.source?.proxyChain,
          "Listener must preserve the real TCP peer and ignore untrusted forwarding headers");
        await mcpExchange(running);
        const before = upstream.requests;
        const git = await request(running.gateway, GIT_PATH, { headers: gatewayAuth(running) });
        check(git.status === 200 && git.body === GIT_BODY && upstream.requests === before + 1,
          `Gateway must authorize and forward the Git route (HTTP ${git.status}, reason ${git.headers["x-agent-access-reason-code"] ?? "none"}, upstream requests ${upstream.requests - before})`);
        for (const path of ["/v1/healthz", "/v1/admin/config/status", "/ui", "/mcp"]) {
          for (const host of [GATEWAY_HOST, "unconfigured.example.test"]) {
            const response = await request(running.gateway, path, { headers: { Host: host, ...gatewayAuth(running) } });
            check(response.status === 404, "Gateway must not mount public routes for any host");
          }
        }
        const misplaced = await request(running.public, GIT_PATH, { headers: { Host: GATEWAY_HOST, ...auth(running) } });
        check(misplaced.status === 404, "Public listener must not mount gateway routes");
        if (publicTls) {
          const session = await connectH2(running.public);
          try {
            check((await h2Request(session, running.public, "/v1/healthz")).status === 200, "HTTP/2 health must succeed");
            await mcpExchange(running, (path, init) => h2Request(session, running.public, path, {
              ...init, headers: Object.fromEntries(Object.entries(init.headers).map(([key, value]) => [key.toLowerCase(), value])),
            }));
          } finally { session.destroy(); }
        }
        if (gatewayTls) {
          const session = await connectH2(running.gateway);
          try {
            const response = await h2Request(session, running.gateway, GIT_PATH, { headers: { authorization: gatewayAuth(running).Authorization } });
            check(response.status === 200 && response.body === GIT_BODY,
              `Gateway must forward Git over HTTP/2 (HTTP ${response.status}, reason ${response.headers["x-agent-access-reason-code"] ?? "none"})`);
            const forwarded = upstream.requests;
            const mismatch = await h2Request(session, running.gateway, GIT_PATH, {
              headers: { authorization: gatewayAuth(running).Authorization, host: "wrong.example.test" },
            });
            check(mismatch.status === 400 && mismatch.headers["x-agent-access-reason-code"] === "gateway_host_invalid"
              && upstream.requests === forwarded, "HTTP/2 authority/Host mismatch must be refused before forwarding");
          } finally { session.destroy(); }
        }
      } finally { await stop(running); }
    });
  }
}

async function expectHandshakeFailure(endpoint, options, label, acceptedCodes) {
  let failure;
  try { (await tlsSocket(endpoint, options)).destroy(); } catch (error) { failure = error; }
  check(failure && acceptedCodes.includes(failure.code), `${label}; expected a TLS verification/protocol rejection (received ${failure?.code ?? "no rejection"})`);
}

async function transportAndRotation(material) {
  const running = await start(await fixture(material, { publicTls: true, gatewayTls: true }));
  const keepalive = new https.Agent({ keepAlive: true, maxCachedSessions: 0, maxSockets: 1 });
  let retainedH2;
  try {
    await test("TLS 1.2/1.3, ALPN, private CA and hostname verification", async () => {
      for (const endpoint of [running.public, running.gateway]) {
        for (const version of ["TLSv1.2", "TLSv1.3"]) {
          const socket = await tlsSocket(endpoint, { minVersion: version, maxVersion: version });
          check(socket.getProtocol() === version && socket.alpnProtocol === "http/1.1", "TLS version and HTTP/1.1 ALPN must match");
          socket.destroy();
        }
        await expectHandshakeFailure(endpoint, { ca: [] }, "Untrusted private CA must be rejected by the client",
          ["SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY"]);
        await expectHandshakeFailure(endpoint, { servername: "wrong.example.test" }, "Hostname mismatch must be rejected by the client", ["ERR_TLS_CERT_ALTNAME_INVALID"]);
        await expectHandshakeFailure(endpoint, { minVersion: "TLSv1", maxVersion: "TLSv1.1", ciphers: "DEFAULT:@SECLEVEL=0" }, "TLS older than 1.2 must be rejected",
          ["ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION", "ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE", "ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE", "ECONNRESET"]);
        let plaintextSucceeded = false;
        try { plaintextSucceeded = (await request({ ...endpoint, secure: false }, "/v1/healthz")).status === 200; } catch { /* TLS-only port rejects plaintext. */ }
        check(!plaintextSucceeded, "TLS listener must never fall back to plaintext HTTP");
      }
    });
    await test("certificate-only SIGUSR2 rotation preserves established H1/H2 connections", async () => {
      const before = await status(running);
      await request(running.public, "/v1/healthz", { agent: keepalive });
      retainedH2 = await connectH2(running.public);
      await h2Request(retainedH2, running.public, "/v1/healthz");
      await replaceIdentity(running.fixture.publicFiles, material.identities[2]);
      await replaceIdentity(running.fixture.gatewayFiles, material.identities[3]);
      running.child.kill("SIGUSR2");
      const after = await until(async () => { const value = await status(running); return value.generation === before.generation + 1 ? value : null; }, "SIGUSR2 certificate publication");
      check(after.configHash === before.configHash, "Certificate-only rotation must not require changed TOML");
      check(await fingerprint(running.public) === material.identities[2].fingerprint, "New public connections must use the replacement identity");
      check(await fingerprint(running.gateway) === material.identities[3].fingerprint, "New gateway connections must use the replacement identity");
      const retained = await request(running.public, "/v1/healthz", { agent: keepalive });
      check(retained.status === 200 && retained.reusedSocket, "Existing HTTP/1.1 connection must survive certificate rotation");
      check((await h2Request(retainedH2, running.public, "/v1/healthz")).status === 200, "Existing HTTP/2 connection must survive certificate rotation");
    });
    await test("failed TLS candidate preserves both identities and the active generation", async () => {
      const before = await status(running);
      await replaceIdentity(running.fixture.publicFiles, material.identities[4]);
      await replacePrivate(running.fixture.gatewayFiles.key, "malformed synthetic private key\n");
      await reload(running, false);
      check((await status(running)).generation === before.generation, "Invalid TLS must preserve the active generation");
      check(await fingerprint(running.public) === material.identities[2].fingerprint, "Valid public candidate must not publish when gateway TLS fails");
      check(await fingerprint(running.gateway) === material.identities[3].fingerprint, "Invalid gateway candidate must preserve its old identity");
      await replaceIdentity(running.fixture.gatewayFiles, material.identities[5]);
    });
    await test("valid TLS with unrelated config failure preserves both identities", async () => {
      const before = await status(running);
      await replacePrivate(running.fixture.configPath, running.fixture.config.replace('node_id = "listener-test"', 'node_id = "changed-node"'));
      await reload(running, false);
      check((await status(running)).generation === before.generation, "Rejected configuration must preserve the active generation");
      check(await fingerprint(running.public) === material.identities[2].fingerprint, "Rejected config must preserve the public identity");
      check(await fingerprint(running.gateway) === material.identities[3].fingerprint, "Rejected config must preserve the gateway identity");
      await replacePrivate(running.fixture.configPath, running.fixture.config);
    });
    await test("admin API publishes both certificate replacements", async () => {
      const before = await status(running);
      await reload(running, true);
      const after = await status(running);
      check(after.generation === before.generation + 1 && after.configHash === before.configHash, "Admin certificate-only reload must advance one generation");
      check(await fingerprint(running.public) === material.identities[4].fingerprint, "Admin reload must publish the public identity");
      check(await fingerprint(running.gateway) === material.identities[5].fingerprint, "Admin reload must publish the gateway identity");
    });
    await test("TLS preserves explicitly trusted client-address forwarding", async () => {
      await replacePrivate(running.fixture.configPath, `${running.fixture.config}\n[network]\ntrusted_proxies = ["127.0.0.1/32"]\n`);
      await reload(running, true);
      const requestId = randomUUID();
      const response = await request(running.public, "/v1/invoke/fake/echo", { method: "POST",
        headers: { ...invocationAuth(running), [REQUEST_ID]: requestId, "X-Forwarded-For": "198.51.100.7" },
        body: { inputs: { project: "TEST", message: "forwarded client" } } });
      check(response.status === 200, "Invocation through configured trusted proxy must succeed");
      const audit = await auditFor(running, requestId);
      check(audit.source?.remote === "198.51.100.7" && audit.source?.proxyChain?.includes("198.51.100.7"),
        "TLS must preserve existing trusted-proxy address resolution");
    });
    keepalive.destroy();
    retainedH2?.destroy();
    await test("HTTP/2 stream cancellation preserves the connection and releases upstream streaming", async () => {
      upstream.streaming = true;
      const session = await connectH2(running.gateway);
      try {
        const stream = session.request({ ":method": "GET", ":path": GIT_PATH, ":authority": GATEWAY_HOST,
          authorization: gatewayAuth(running).Authorization });
        stream.on("error", () => {});
        stream.resume();
        const [headers] = await bounded(once(stream, "response"), REQUEST_TIMEOUT, "Streaming gateway response");
        check(headers[":status"] === 200, "Streaming gateway request must be admitted");
        await until(() => upstream.streams.size === 1, "Upstream streaming response");
        stream.close(http2.constants.NGHTTP2_CANCEL);
        await until(() => upstream.streams.size === 0, "Canceled HTTP/2 upstream release");
        upstream.streaming = false;
        check((await h2Request(session, running.gateway, GIT_PATH, { headers: { authorization: gatewayAuth(running).Authorization } })).status === 200, "One canceled HTTP/2 stream must not terminate its connection");
      } finally { upstream.streaming = false; session.destroy(); }
    });
    await test("stalled TLS handshake does not block healthy clients", async () => {
      const stalled = await tcp(running.public.port);
      try {
        const started = Date.now();
        check((await request(running.public, "/v1/healthz")).status === 200, "Valid TLS client must progress while another handshake is stalled");
        check(Date.now() - started < HANDSHAKE_TIMEOUT, "Valid TLS client must not wait for the stalled handshake timeout");
        await until(() => stalled.destroyed, "Stalled TLS handshake timeout", HANDSHAKE_TIMEOUT + 3_000);
      } finally { stalled.destroy(); }
    });
    await test("handshake concurrency cap rejects excess work and recovers", async () => {
      const stalled = await Promise.all(Array.from({ length: HANDSHAKE_CAPACITY }, () => tcp(running.public.port)));
      try {
        await delay(100);
        check(stalled.every((socket) => !socket.destroyed), "Capacity test must occupy all handshake slots");
        const excess = await tcp(running.public.port);
        try { await until(() => excess.destroyed, "Excess TLS handshake rejection", 1_500); }
        finally { excess.destroy(); }
        check((await request(running.gateway, GIT_PATH, { headers: gatewayAuth(running) })).status === 200, "Public handshake saturation must not exhaust the gateway's separate budget");
        await until(() => stalled.every((socket) => socket.destroyed), "Bounded handshake release", HANDSHAKE_TIMEOUT + 3_000);
        check((await request(running.public, "/v1/healthz")).status === 200, "TLS listener must recover after handshake timeouts");
      } finally { for (const socket of stalled) socket.destroy(); }
    });
    await test("shutdown joins pending handshakes and active TLS streaming connections", async () => {
      const pending = await tcp(running.public.port);
      const established = await tlsSocket(running.public);
      established.resume();
      established.write(`GET /v1/healthz HTTP/1.1\r\nHost: ${HOST}\r\n`);
      upstream.streaming = true;
      const session = await connectH2(running.gateway);
      const stream = session.request({ ":method": "GET", ":path": GIT_PATH, ":authority": GATEWAY_HOST,
        authorization: gatewayAuth(running).Authorization });
      stream.on("error", () => {});
      stream.resume();
      await bounded(once(stream, "response"), REQUEST_TIMEOUT, "Active TLS streaming response");
      const started = Date.now();
      await stop(running);
      check(Date.now() - started < 5_000, "Shutdown must remain bounded with pending TLS work");
      await until(() => pending.destroyed && established.destroyed && !sessions.has(session), "TLS connections closed by shutdown");
      await until(() => upstream.streams.size === 0, "Shutdown releases upstream stream");
      upstream.streaming = false;
    });
  } finally {
    keepalive.destroy();
    retainedH2?.destroy();
    upstream.streaming = false;
    await stop(running);
  }
}

async function invalidStartups(material) {
  const scenarios = [
    ["missing certificate", async (value) => fs.rm(value.publicFiles.cert)],
    ["missing key", async (value) => fs.rm(value.publicFiles.key)],
    ["malformed certificate", async (value) => writePrivate(value.publicFiles.cert, "not a certificate\n")],
    ["malformed key", async (value) => writePrivate(value.publicFiles.key, "not a private key\n")],
    ["mismatched certificate and key", async (value) => writePrivate(value.publicFiles.key, material.identities[1].key)],
    ["incomplete public TLS flags", async (value) => { const index = value.args.indexOf("--tls-private-key"); value.args.splice(index, 2); }],
    ["incomplete gateway TLS flags", async (value) => { const index = value.args.indexOf("--gateway-tls-cert-chain"); value.args.splice(index, 2); }],
    ["gateway TLS without a gateway listener", async (value) => { const index = value.args.indexOf("--gateway-listen"); value.args.splice(index, 2); }],
  ];
  for (const [name, prepare] of scenarios) {
    await test(`startup rejects ${name}`, async () => {
      const value = await fixture(material, { publicTls: true, gatewayTls: true });
      await prepare(value);
      const running = launch(value);
      const result = await bounded(running.closed, START_TIMEOUT, "Invalid TLS startup");
      check(result.code !== null && result.code !== 0, "Invalid TLS configuration must fail startup");
      check(!running.events.some((event) => event.event === "broker_listening"), "Invalid TLS configuration must not activate any listener");
      check(!running.log.includes("-----BEGIN PRIVATE KEY-----"), "Startup error must not expose private-key material");
    });
  }
  await test("occupied gateway port fails startup without a surviving public listener", async () => {
    const occupied = net.createServer((socket) => socket.destroy());
    await new Promise((done) => occupied.listen(0, "127.0.0.1", done));
    try {
      const value = await fixture(material, { publicTls: true, gatewayTls: true });
      value.args[value.args.indexOf("--gateway-listen") + 1] = `127.0.0.1:${occupied.address().port}`;
      const running = launch(value);
      const result = await bounded(running.closed, START_TIMEOUT, "Occupied-port startup");
      check(result.code !== null && result.code !== 0, "Occupied port must fail startup");
      check(!running.events.some((event) => event.event === "broker_listening"), "All binds must succeed before a listener is activated");
    } finally { await new Promise((done) => occupied.close(done)); }
  });
}

async function browserContract(material) {
  await test("HTTPS portal route, canonical origin, Secure cookie and CSRF", async () => {
    const running = await start(await fixture(material, { publicTls: true, gateway: false, browser: true }));
    try {
      const page = await request(running.public, "/ui");
      check(page.status === 200 && page.body.includes("Native TLS fixture"), "HTTPS listener must serve the portal route");
      const body = { principalId: "admin", password: running.fixture.initialPassword, returnTo: "/ui" };
      const wrongOrigin = await request(running.public, "/v1/auth/local/login", { method: "POST", headers: { Origin: "https://wrong.example.test" }, body });
      check(wrongOrigin.status === 403, "Native TLS must preserve browser origin rejection");
      const login = await request(running.public, "/v1/auth/local/login", { method: "POST", headers: { Origin: `https://${HOST}` }, body });
      check(login.status === 200, "Browser login over native HTTPS must succeed");
      const cookie = login.headers["set-cookie"]?.[0];
      check(cookie?.includes("; Secure") && cookie.includes("HttpOnly") && cookie.includes("Path=/v1"), "HTTPS browser cookie must preserve Secure/HttpOnly/path attributes");
      const sessionCookie = secret(cookie.split(";")[0]);
      const csrf = secret(json(login).result.csrfToken);
      const newPassword = secret(`fixture-updated-${randomBytes(18).toString("hex")}`);
      const headers = { Cookie: sessionCookie, Origin: `https://${HOST}` };
      const changeBody = { currentPassword: running.fixture.initialPassword, newPassword };
      const refused = await request(running.public, "/v1/auth/local/password/change", { method: "POST", headers, body: changeBody });
      check(refused.status === 403, "Cookie-authenticated mutation without CSRF must be rejected");
      const changed = await request(running.public, "/v1/auth/local/password/change", { method: "POST", headers: { ...headers, "X-Agent-Access-CSRF": csrf }, body: changeBody });
      check(changed.status === 200 && json(changed).result.passwordChangeRequired === false, "Cookie-authenticated mutation with CSRF must succeed over TLS");
    } finally { await stop(running); }
  });
}

async function cleanup() {
  for (const session of sessions) session.destroy();
  for (const socket of sockets) socket.destroy();
  for (const running of children) {
    try { await stop(running, false); } catch { /* stop already escalated and joined. */ }
  }
  await upstream?.close();
  try {
    if (options?.output) {
      for (const [index, running] of [...children].entries()) {
        const safeEvents = running.events.map(({ event, listener, address, generation, activeGeneration, reasonCode }) =>
          ({ event, listener, address, generation, activeGeneration, reasonCode }));
        await writePrivate(join(options.output, `process-${index + 1}.json`), `${JSON.stringify({ exit: running.result, events: safeEvents }, null, 2)}\n`);
        if (report?.status === "failed") await writePrivate(join(options.output, `process-${index + 1}.log`), sanitized(running.log));
      }
    }
  } finally {
    if (temporary) await fs.rm(temporary, { recursive: true, force: true });
  }
}

async function main() {
  options = argumentsOf(process.argv.slice(2));
  if (options.help) {
    console.log("Usage: node scripts/verify-listener-tls.mjs --broker /absolute/path/to/fresh/agent-access-broker [--output-dir /new-or-empty/evidence]\nRequires Unix, Node.js and openssl. Runs isolated executable acceptance; does not build or deploy.");
    return;
  }
  check(process.platform !== "win32", "This executable harness requires Unix SIGUSR2/SIGTERM; it is not Windows qualification");
  await fs.access(options.broker, constants.X_OK);
  if (options.output) {
    await fs.mkdir(options.output, { recursive: true, mode: 0o700 });
    check((await fs.readdir(options.output)).length === 0, "--output-dir must be new or empty");
  }
  const binaryHash = createHash("sha256");
  for await (const chunk of createReadStream(options.broker)) binaryHash.update(chunk);
  report = { schemaVersion: 1, startedAt: new Date().toISOString(), status: "running",
    broker: { path: options.broker, sha256: binaryHash.digest("hex") },
    node: process.version, platform: `${process.platform}-${process.arch}`,
    openssl: execFileSync("openssl", ["version"], { encoding: "utf8" }).trim(), cases,
    limitations: ["Uses a synthetic Git HTTP upstream and a minimal portal document; no live provider or browser rendering.",
      "The supplied executable must be freshly built with production features; this harness records its hash and does not build or certify its source provenance."] };
  temporary = await fs.mkdtemp(join(tmpdir(), "aab-listener-tls-"));
  await fs.chmod(temporary, 0o700);
  const interruptedBySignal = () => {
    interrupted = true;
    for (const running of children) if (!running.exited) running.child.kill("SIGTERM");
  };
  process.on("SIGINT", interruptedBySignal);
  process.on("SIGTERM", interruptedBySignal);
  const oldMask = process.umask(0o077);
  try {
    const material = await certificates();
    upstream = await startUpstream(material);
    await listenerModes(material);
    await transportAndRotation(material);
    await invalidStartups(material);
    await browserContract(material);
    report.status = "passed";
  } catch (error) {
    report.status = "failed";
    report.error = sanitized(error.message);
    throw error;
  } finally {
    await cleanup();
    process.umask(oldMask);
    process.off("SIGINT", interruptedBySignal);
    process.off("SIGTERM", interruptedBySignal);
    report.finishedAt = new Date().toISOString();
    if (options.output) await writePrivate(join(options.output, "REPORT.json"), `${JSON.stringify(report, null, 2)}\n`);
  }
  console.log(`Passed ${cases.length} listener TLS acceptance checks; all isolated processes and private fixtures removed.`);
  if (options.output) console.log(`Evidence: ${join(options.output, "REPORT.json")}`);
}

main().catch((error) => {
  console.error(`Listener TLS verification failed: ${sanitized(error.message)}`);
  process.exitCode = 1;
});
