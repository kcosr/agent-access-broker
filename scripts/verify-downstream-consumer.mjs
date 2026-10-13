#!/usr/bin/env node
// Stage an independent provider repository and a downstream broker assembly
// from one clean candidate commit, build and test them with locked offline
// Cargo against the shared download cache, and run the assembled broker.
// See tests/downstream-consumer/README.md. This command never publishes.
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { accessSync, chmodSync, closeSync, constants, copyFileSync, existsSync, mkdirSync, mkdtempSync,
  openSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { devNull, homedir, tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertNoGitOverrides } from "./release-environment.mjs";
import { assertQualificationSource, qualificationOutputDirectory } from "./verify-release.mjs";
import { cargoConfigInventory, inspectLocalToolchain } from "./verify-release-provenance.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const ROOT = resolve(dirname(SCRIPT_PATH), "..");

export const CANONICAL_UPSTREAM_URL = "https://github.com/kcosr/agent-access-broker.git";
export const CANONICAL_PROVIDER_URL = "https://git.example.com/provider-team/conformance-provider.git";
export const SENTINEL_REV = "0".repeat(40);
export const CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index";
export const SDK_PACKAGE = "agent-access-provider";
export const PROVIDER_PACKAGE = "agent-access-conformance";
export const ASSEMBLY_PACKAGE = "downstream-broker";
const PROVIDER_CRATE_DIRECTORY = "crates/agent-access-conformance";
const FIXTURE_DIRECTORY = "tests/downstream-consumer";
const FULL_SHA1 = /^[0-9a-f]{40}$/;
// Roles a reference provider repository must not reach through any edge.
const FORBIDDEN_PROVIDER_ROLES = Object.freeze(["core", "host", "assembly", "cli", "adapter"]);
const ASSEMBLY_EDITION = "2024";
const SYNTHETIC_LOG = "downstream consumer log line\n";
const READY_TIMEOUT_MS = 60_000;
const PROCESS_TIMEOUT_MS = 60_000;
const SHUTDOWN_TIMEOUT_MS = 30_000;
const stamp = () => new Date().toISOString();
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const USAGE = "Usage: node scripts/verify-downstream-consumer.mjs --commit <full-sha> "
  + "--evidence-dir /absolute/new/directory --cli /absolute/path/to/agent-access [--source staged|canonical]";

export function parseConsumerArguments(args) {
  const keys = { "--commit": "commit", "--evidence-dir": "evidenceDir", "--cli": "cli", "--source": "source" };
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = keys[args[index]];
    if (!key || Object.hasOwn(options, key) || index + 1 >= args.length) throw new Error(USAGE);
    options[key] = args[index + 1];
  }
  options.source ??= "staged";
  if (!FULL_SHA1.test(options.commit ?? "") || !isAbsolute(options.evidenceDir ?? "")
      || !isAbsolute(options.cli ?? "") || !["staged", "canonical"].includes(options.source)) {
    throw new Error(USAGE);
  }
  return options;
}

// A strict reader for the single-line values fixture manifests use: basic
// strings without escapes, booleans, integers, arrays and inline tables.
// Anything else fails rather than being skipped.
export function parseTomlValue(source) {
  let position = 0;
  const fail = () => { throw new Error(`Unsupported manifest value: ${source.trim()}`); };
  const space = () => { while (source[position] === " " || source[position] === "\t") position += 1; };
  const value = () => {
    space();
    const character = source[position];
    if (character === "\"") {
      const end = source.indexOf("\"", position + 1);
      if (end < 0 || source.slice(position + 1, end).includes("\\")) fail();
      const text = source.slice(position + 1, end);
      position = end + 1;
      return text;
    }
    if (character === "[") {
      position += 1;
      const items = [];
      space();
      while (source[position] !== "]") {
        items.push(value());
        space();
        if (source[position] === ",") { position += 1; space(); }
        else if (source[position] !== "]") fail();
      }
      position += 1;
      return items;
    }
    if (character === "{") {
      position += 1;
      const table = {};
      space();
      while (source[position] !== "}") {
        const key = /^[A-Za-z0-9_-]+/.exec(source.slice(position))?.[0];
        if (!key || Object.hasOwn(table, key)) fail();
        position += key.length;
        space();
        if (source[position] !== "=") fail();
        position += 1;
        table[key] = value();
        space();
        if (source[position] === ",") {
          position += 1;
          space();
          if (source[position] === "}") fail();
        } else if (source[position] !== "}") fail();
      }
      position += 1;
      return table;
    }
    const literal = /^(?:true|false|-?\d+)/.exec(source.slice(position))?.[0];
    if (!literal) fail();
    position += literal.length;
    return literal === "true" ? true : literal === "false" ? false : Number(literal);
  };
  const parsed = value();
  space();
  if (position < source.length && source[position] !== "#") fail();
  return parsed;
}

const TABLE_HEADER = /^\s*\[\[?\s*([^\]]*?)\s*\]\]?\s*(?:#.*)?$/;
const DEPENDENCY_TABLE = /(?:^|\.)(?:dev-|build-)?dependencies$/;
const DEPENDENCY_ENTRY = /^\s*([A-Za-z0-9_-]+)(\.workspace)?\s*=\s*(.*)$/;

// Lists every dependency entry of a manifest, including workspace
// dependencies. Source overrides and table-form dependencies are rejected
// so that no dependency escapes the source checks.
export function manifestDependencies(text) {
  const lines = text.split("\n");
  const entries = [];
  let table = "";
  lines.forEach((line, index) => {
    const content = line.trim();
    if (!content || content.startsWith("#")) return;
    const header = TABLE_HEADER.exec(line);
    if (header) {
      table = header[1];
      if (/^(?:patch|replace)(?:\.|$)/.test(table)) {
        throw new Error(`Fixture manifests must not override sources with [${table}]`);
      }
      if (/(?:^|\.)(?:dev-|build-)?dependencies\./.test(table)) {
        throw new Error(`Write [${table}] as one inline dependency entry`);
      }
      return;
    }
    if (!DEPENDENCY_TABLE.test(table)) return;
    const entry = DEPENDENCY_ENTRY.exec(line);
    if (!entry) throw new Error(`Unsupported dependency entry on line ${index + 1}: ${content}`);
    const value = parseTomlValue(entry[3]);
    let spec;
    if (entry[2]) {
      if (value !== true) throw new Error(`Unsupported dependency entry on line ${index + 1}: ${content}`);
      spec = { workspace: true };
    } else if (typeof value === "string") {
      spec = { version: value };
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      spec = value;
    } else {
      throw new Error(`Unsupported dependency entry on line ${index + 1}: ${content}`);
    }
    entries.push({ index, line: index + 1, table, key: entry[1], name: spec.package ?? entry[1], spec });
  });
  return { lines, entries };
}

export function lastTableHeader(text) {
  return text.split("\n").map((line) => TABLE_HEADER.exec(line)?.[1]).filter(Boolean).at(-1) ?? null;
}

// Maps the canonical upstream and provider URLs with the sentinel revision to
// their staged sources. `sources` lists { canonical, url, rev, packages } in
// precedence order; a package name belongs to the first source listing it.
// Every other spelling of an upstream or provider dependency is rejected.
export function rewriteStagedManifest(text, sources) {
  const { lines, entries } = manifestDependencies(text);
  const rewrites = [];
  for (const entry of entries) {
    const { spec } = entry;
    const where = `line ${entry.line} (${entry.table}: ${entry.key})`;
    const expected = sources.find((source) => source.packages.has(entry.name));
    for (const field of ["path", "branch", "tag", "registry", "registry-index"]) {
      if (spec[field] !== undefined) {
        throw new Error(`${where}: fixture dependencies must not use ${field}; use a git URL with a full rev or a registry version`);
      }
    }
    if (spec.git === undefined) {
      if (spec.rev !== undefined) throw new Error(`${where}: rev requires a git URL`);
      if (expected && spec.workspace !== true) {
        throw new Error(`${where}: ${entry.name} must use ${expected.canonical} with the full sentinel rev`);
      }
      continue;
    }
    if (!expected) throw new Error(`${where}: ${entry.name} must not use a git source`);
    if (spec.git !== expected.canonical) {
      throw new Error(`${where}: ${entry.name} must use exactly ${expected.canonical}; found ${spec.git}`);
    }
    if (spec.rev !== SENTINEL_REV) {
      throw new Error(`${where}: ${entry.name} must pin the sentinel rev ${SENTINEL_REV}; found ${spec.rev ?? "none"}`);
    }
    if (spec.version !== undefined || spec.workspace !== undefined) {
      throw new Error(`${where}: ${entry.name} must not combine its git pin with version or workspace`);
    }
    const original = lines[entry.index];
    const urlLiteral = `"${spec.git}"`;
    const revLiteral = `"${SENTINEL_REV}"`;
    if (original.split(urlLiteral).length !== 2 || original.split(revLiteral).length !== 2) {
      throw new Error(`${where}: the git URL and rev must each appear once`);
    }
    lines[entry.index] = original.replace(urlLiteral, JSON.stringify(expected.url)).replace(revLiteral, JSON.stringify(expected.rev));
    rewrites.push({ line: entry.line, table: entry.table, package: entry.name,
      canonical: { git: spec.git, rev: SENTINEL_REV }, staged: { git: expected.url, rev: expected.rev } });
  }
  const rewritten = lines.join("\n");
  if (rewritten.includes(SENTINEL_REV)) throw new Error("A sentinel rev remains outside a recognized dependency entry");
  return { text: rewritten, rewrites };
}

// Re-homes the archived provider crate: its SDK path dependency becomes the
// provider repository's own workspace pin. Any other path dependency on
// upstream code means the crate is no longer SDK-only and fails the check.
export function normalizeProviderCrateManifest(text) {
  const { lines, entries } = manifestDependencies(text);
  const inherited = new Set();
  for (const entry of entries) {
    const { spec, key } = entry;
    if (spec.git !== undefined) throw new Error(`${PROVIDER_PACKAGE} has an unexpected git dependency on ${entry.name}`);
    if (spec.path !== undefined) {
      if (key !== SDK_PACKAGE || entry.name !== SDK_PACKAGE) {
        throw new Error(`${PROVIDER_PACKAGE} may depend on upstream crates only through ${SDK_PACKAGE}; found a path dependency on ${entry.name}`);
      }
      const unsupported = Object.keys(spec).filter((field) => !["path", "features", "optional"].includes(field));
      if (unsupported.length) throw new Error(`${PROVIDER_PACKAGE}: unsupported ${SDK_PACKAGE} fields ${unsupported.join(", ")}`);
      const fields = ["workspace = true"];
      if (spec.features) fields.push(`features = [${spec.features.map((feature) => JSON.stringify(feature)).join(", ")}]`);
      if (spec.optional !== undefined) fields.push(`optional = ${spec.optional}`);
      const indent = /^\s*/.exec(lines[entry.index])[0];
      lines[entry.index] = fields.length === 1 ? `${indent}${key}.workspace = true` : `${indent}${key} = { ${fields.join(", ")} }`;
      continue;
    }
    if (spec.workspace === true && key !== SDK_PACKAGE) inherited.add(key);
  }
  return { text: lines.join("\n"), inherited: [...inherited].sort() };
}

// The candidate root's workspace dependency lines that the provider crate
// inherits, copied verbatim so the staged crate keeps identical requirements.
export function inheritedWorkspaceDependencies(rootManifest, names) {
  const { lines, entries } = manifestDependencies(rootManifest);
  const available = new Map(entries.filter((entry) => entry.table === "workspace.dependencies")
    .map((entry) => [entry.key, entry]));
  return names.map((name) => {
    const entry = available.get(name);
    if (!entry) throw new Error(`The candidate root manifest defines no workspace dependency ${name}`);
    if (entry.spec.git !== undefined || entry.spec.path !== undefined) {
      throw new Error(`Workspace dependency ${name} is not a registry dependency`);
    }
    return lines[entry.index].trim();
  });
}

export function parseLockfile(text) {
  const [header, ...blocks] = text.split(/^\[\[package\]\]$/m);
  const version = Number(/^version = (\d+)$/m.exec(header)?.[1]);
  if (version !== 4) throw new Error(`Unsupported Cargo.lock format version ${version}`);
  const packages = blocks.map((block) => {
    if (/^\[/m.test(block)) throw new Error("Cargo.lock contains an unsupported table");
    const field = (name) => new RegExp(`^${name} = "([^"]*)"$`, "m").exec(block)?.[1] ?? null;
    const name = field("name");
    const packageVersion = field("version");
    if (!name || !packageVersion) throw new Error("Cargo.lock package lacks a name or version");
    const dependencies = /^dependencies = \[([\s\S]*?)^\]$/m.exec(block)?.[1];
    return { name, version: packageVersion, source: field("source"), checksum: field("checksum"),
      dependencies: dependencies ? [...dependencies.matchAll(/"([^"]+)"/g)].map((match) => match[1]) : [],
      block: `[[package]]${block}` };
  });
  return { version, header, packages };
}

// Seeds a staged lockfile with the candidate's third-party entries only, so
// the setup resolution keeps every registry version and checksum.
export function thirdPartyLockSeed(text) {
  const lock = parseLockfile(text);
  const unsupported = lock.packages.filter((entry) => entry.source !== null && entry.source !== CRATES_IO_SOURCE);
  if (unsupported.length) {
    throw new Error(`The candidate Cargo.lock has unsupported sources: ${unsupported.map((entry) => `${entry.name} ${entry.source}`).join(", ")}`);
  }
  const seeded = lock.packages.filter((entry) => entry.source === CRATES_IO_SOURCE).map((entry) => entry.block).join("");
  return `${lock.header}${seeded}`.replace(/\n*$/, "\n");
}

export const gitSourceId = (url, rev) => `git+${url}?rev=${rev}#${rev}`;

// Reviews the staged lockfiles against the candidate: upstream packages come
// only from the one upstream source, the provider crate only from its own
// repository, one SDK package ID spans both graphs, and every third-party
// entry is a candidate entry with the same version and checksum.
export function reviewLockfiles({ candidate, staged, upstreamSource, providerSource }) {
  const upstreamNames = new Set(candidate.packages.filter((entry) => entry.source === null).map((entry) => entry.name));
  const thirdParty = new Map(candidate.packages.filter((entry) => entry.source !== null)
    .map((entry) => [`${entry.name} ${entry.version} ${entry.source}`, entry]));
  const errors = [];
  const sdkIds = new Set();
  const summary = [];
  for (const { repository, lock, members } of staged) {
    const counts = { workspace: 0, upstream: 0, provider: 0, thirdParty: 0 };
    for (const entry of lock.packages) {
      const id = `${entry.name} ${entry.version} (${entry.source ?? "workspace path"})`;
      if (entry.name === SDK_PACKAGE) sdkIds.add(`${entry.name} ${entry.version} ${entry.source}`);
      if (entry.source === null) {
        if (members.includes(entry.name)) counts.workspace += 1;
        else errors.push(`${repository}: ${id} is a path package outside the staged workspace`);
      } else if (entry.source === providerSource) {
        if (entry.name === PROVIDER_PACKAGE) counts.provider += 1;
        else errors.push(`${repository}: ${id} is not a provider repository package`);
      } else if (entry.source === upstreamSource) {
        if (entry.name === PROVIDER_PACKAGE) errors.push(`${repository}: ${id} must come from the provider repository`);
        else if (upstreamNames.has(entry.name)) counts.upstream += 1;
        else errors.push(`${repository}: ${id} is not a candidate workspace package`);
      } else if (upstreamNames.has(entry.name)) {
        errors.push(`${repository}: ${id} names an upstream package but does not resolve to ${upstreamSource}`);
      } else if (entry.source !== CRATES_IO_SOURCE) {
        errors.push(`${repository}: ${id} has an unexpected source`);
      } else {
        const locked = thirdParty.get(`${entry.name} ${entry.version} ${entry.source}`);
        if (!locked) errors.push(`${repository}: ${id} is not in the candidate Cargo.lock`);
        else if (locked.checksum !== entry.checksum) errors.push(`${repository}: ${id} checksum differs from the candidate Cargo.lock`);
        else counts.thirdParty += 1;
      }
    }
    for (const member of members) {
      if (!lock.packages.some((entry) => entry.name === member && entry.source === null)) {
        errors.push(`${repository}: workspace member ${member} is missing from Cargo.lock`);
      }
    }
    if (!lock.packages.some((entry) => entry.name === SDK_PACKAGE)) errors.push(`${repository}: ${SDK_PACKAGE} is not in the graph`);
    summary.push({ repository, packages: lock.packages.length, ...counts });
  }
  if (sdkIds.size !== 1) {
    errors.push(`Expected exactly one ${SDK_PACKAGE} package ID across the staged graphs; found ${[...sdkIds].join(", ") || "none"}`);
  }
  return { errors, summary, sdkPackageIds: [...sdkIds] };
}

export function featureViolations(tree) {
  return tree.split("\n").filter((line) => /feature "test-support"/.test(line)).map((line) => line.trim());
}

export function providerBoundaryViolations(metadata) {
  return (metadata.packages ?? []).filter((entry) => FORBIDDEN_PROVIDER_ROLES.includes(entry.metadata?.["agent-access"]?.role))
    .map((entry) => `${entry.name} ${entry.version} (${entry.metadata["agent-access"].role}) is in the provider repository graph`);
}

export function assertAssemblyStatus(status, { version }) {
  if (status?.brokerVersion !== version || status.buildProvenance !== "unavailable" || (status.buildCommit ?? null) !== null) {
    throw new Error(`Status must report the assembly's own version ${version} with unavailable provenance; received ${JSON.stringify(status)}`);
  }
}

export function toolchainChannel(text) {
  return /^\s*channel\s*=\s*"([^"]+)"\s*$/m.exec(text)?.[1] ?? null;
}

// Removes inherited Cargo, compiler and broker settings. The driver supplies
// its own Cargo home, compiler paths and process configuration; only the
// build parallelism passes through.
export function sanitizedEnvironment(env) {
  const removed = [];
  const result = {};
  for (const [name, value] of Object.entries(env)) {
    if (name === "CARGO_BUILD_JOBS") {
      result[name] = value;
    } else if (/^CARGO(?:_|$)/.test(name) || /^RUSTC(?:_|$)/.test(name) || /^RUSTDOC(?:_|$)/.test(name)
        || ["RUSTFLAGS", "RUSTDOCFLAGS", "RUSTUP_TOOLCHAIN", "RUST_TARGET_PATH", "RUST_LOG"].includes(name)
        || /^(?:(?:HOST|TARGET)_)?(?:CC|CXX|AR|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS)(?:_|$)/.test(name)
        || name.startsWith("AGENT_ACCESS_") || name.startsWith("AAB_")) {
      removed.push(name);
    } else {
      result[name] = value;
    }
  }
  return { env: result, removed: removed.sort() };
}

function isInside(parent, child) {
  const path = relative(parent, child);
  return !path || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

function brokerConfiguration({ run, port, development }) {
  const file = (name) => JSON.stringify(`file:${join(run, name)}`);
  const controller = `http://127.0.0.1:${port}`;
  return `[deployment]
environment = "development"
enable_fake_service = ${development}

[identity]
mode = "required"
authority = "toml"

[[identity.sources]]
name = "downstream"
type = "static_principals"
header = "X-Agent-Access-Identity-Token"
scheme = "raw"

[[identity.sources.principals]]
principal = "ci-agent"
token_refs = [${file("principal-token")}]

[credentials.service.cloudbees_ci]
type = "basic_api_token"
username_ref = ${file("cloudbees-username")}
token_ref = ${file("cloudbees-token")}

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "payments-job"
resource_type = "cloudbees_ci_job"
selector = { kind = "exact", value = "team-ci/payments/build-api" }
allowed_execution_contexts = ["default"]
enabled = true

[[policy.grants]]
subjects = ["user:ci-agent"]
service = "cloudbees_ci"
actions = ["build.log.read"]
resources = { resource_ids = ["payments-job"] }
credential_mode = "service"

[providers.cloudbees_ci]
allowed_upstream_hosts = ["${controller}/team-ci/**"]

[providers.cloudbees_ci.controllers.team-ci]
base_url = "${controller}/team-ci/"

[providers.conformance]
base_url = "${controller}/conformance"
allowed_upstream_hosts = ["${controller}/conformance/**"]

[audit]
type = "jsonl"
path = ${JSON.stringify(join(run, "audit.jsonl"))}
`;
}

function startSyntheticController() {
  const requests = [];
  const server = createServer((request, response) => {
    const url = new URL(request.url, "http://controller.invalid");
    requests.push({ method: request.method, url: request.url, authorization: request.headers.authorization ?? null });
    if (request.method === "GET" && url.pathname === "/team-ci/job/payments/job/build-api/42/consoleText") {
      response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      response.end(SYNTHETIC_LOG);
      return;
    }
    response.writeHead(404, { "content-type": "text/plain" });
    response.end("not found\n");
  });
  return new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolvePromise({
      port: server.address().port,
      requests,
      close: () => new Promise((done) => { server.closeAllConnections(); server.close(() => done()); }),
    }));
  });
}

function freeLoopbackPort() {
  return new Promise((resolvePromise, reject) => {
    const server = createNetServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close((error) => (error ? reject(error) : resolvePromise(port)));
    });
  });
}

function runProcess(command, args, { env, cwd, timeoutMs = PROCESS_TIMEOUT_MS }) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { env, cwd, stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolvePromise({ code, signal, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") });
    });
  });
}

async function waitForReady(url, child) {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  let last = "no response";
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`The assembled broker exited before readiness with ${child.exitCode ?? child.signalCode}`);
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
      last = `HTTP ${response.status}`;
    } catch (error) {
      last = error.message;
    }
    await new Promise((done) => setTimeout(done, 200));
  }
  throw new Error(`The assembled broker was not ready: ${last}`);
}

function waitForExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return Promise.race([
    new Promise((done) => child.once("exit", () => done(true))),
    new Promise((done) => setTimeout(() => done(false), timeoutMs)),
  ]);
}

// Starts the built assembly against a synthetic CloudBees controller, checks
// readiness, status identity and one read through the CLI, then stops it.
async function processAcceptance({ binary, cli, run, evidence, env, version, platform }) {
  mkdirSync(run, { recursive: true, mode: 0o700 });
  const output = join(evidence, "acceptance");
  mkdirSync(output, { recursive: true, mode: 0o700 });
  const principalToken = randomBytes(24).toString("hex");
  const cloudbeesToken = randomBytes(24).toString("hex");
  for (const [name, value] of [["principal-token", principalToken], ["cloudbees-username", "automation"], ["cloudbees-token", cloudbeesToken]]) {
    writeFileSync(join(run, name), value, { mode: 0o600 });
  }
  const expectedAuthorization = `Basic ${Buffer.from(`automation:${cloudbeesToken}`).toString("base64")}`;
  const result = { checks: [] };
  const check = (id, passed, detail) => {
    result.checks.push({ id, passed, ...(detail === undefined ? {} : { detail }) });
    if (!passed) throw new Error(`Process acceptance failed: ${id}${detail === undefined ? "" : ` (${typeof detail === "string" ? detail : JSON.stringify(detail)})`}`);
  };
  const controller = await startSyntheticController();
  try {
    const port = await freeLoopbackPort();
    const configPath = join(run, "broker.toml");
    const gatedPath = join(run, "broker-without-development.toml");
    writeFileSync(configPath, brokerConfiguration({ run, port: controller.port, development: true }), { mode: 0o600 });
    writeFileSync(gatedPath, brokerConfiguration({ run, port: controller.port, development: false }), { mode: 0o600 });
    copyFileSync(configPath, join(output, "broker.toml"));

    const gated = await runProcess(binary, ["--config", gatedPath, "config", "validate"], { env, cwd: run });
    writeFileSync(join(output, "config-validate-without-development.log"), `${gated.stdout}${gated.stderr}`);
    check("development-provider-requires-fixtures", gated.code === 3 && gated.stderr.includes("providers.conformance"),
      { exitCode: gated.code });
    const validated = await runProcess(binary, ["--config", configPath, "config", "validate"], { env, cwd: run });
    writeFileSync(join(output, "config-validate.log"), `${validated.stdout}${validated.stderr}`);
    check("config-validate", validated.code === 0, { exitCode: validated.code });

    const base = `http://127.0.0.1:${port}`;
    const log = openSync(join(output, "broker.log"), "w", 0o600);
    const broker = spawn(binary, ["--config", configPath, "serve", "--listen", `127.0.0.1:${port}`],
      { env, cwd: run, stdio: ["ignore", log, log] });
    let stopped = false;
    try {
      await waitForReady(`${base}/v1/readyz`, broker);
      check("readyz", true);
      const health = await fetch(`${base}/v1/healthz`);
      check("healthz", health.ok, { status: health.status });
      const anonymous = await fetch(`${base}/v1/broker/status`, { headers: { "X-Agent-Access-Request-Id": "downstream-consumer-anonymous" } });
      const anonymousBody = await anonymous.json().catch(() => null);
      check("status-requires-identity", anonymous.status === 401 && anonymousBody?.reasonCode === "identity_required",
        { status: anonymous.status, reasonCode: anonymousBody?.reasonCode });
      const statusResponse = await fetch(`${base}/v1/broker/status`, {
        headers: { "X-Agent-Access-Identity-Token": principalToken, "X-Agent-Access-Request-Id": "downstream-consumer-status" },
      });
      const status = await statusResponse.json();
      writeFileSync(join(output, "status.json"), `${JSON.stringify(status, null, 2)}\n`);
      check("status-ok", statusResponse.ok, { status: statusResponse.status });
      assertAssemblyStatus(status, { version });
      check("status-assembly-identity", true, { brokerVersion: status.brokerVersion, buildProvenance: status.buildProvenance });

      const clientConfig = join(run, "client.toml");
      writeFileSync(clientConfig, `[service]\nurl = ${JSON.stringify(base)}\n\n[identity]\nheader = "X-Agent-Access-Identity-Token"\nscheme = "raw"\ntoken_file = ${JSON.stringify(join(run, "principal-token"))}\n`, { mode: 0o600 });
      const invoke = (job) => runProcess(cli, ["--config", clientConfig, "invoke", "cloudbees_ci.build.log.read", "--input-json",
        JSON.stringify({ controller: "team-ci", job, buildNumber: 42, maxBytes: 1024 }), "--output", "-"], { env, cwd: run });
      const allowed = await invoke("payments/build-api");
      writeFileSync(join(output, "cli-allowed.json"), allowed.stdout);
      writeFileSync(join(output, "cli-allowed.stderr.log"), allowed.stderr);
      check("cli-read-exit", allowed.code === 0, { exitCode: allowed.code });
      const read = JSON.parse(allowed.stdout);
      check("cli-read-result", read.decision === "allow" && read.result?.text === SYNTHETIC_LOG,
        { decision: read.decision, reachedEnd: read.result?.reachedEnd });
      const denied = await invoke("payments/other-job");
      writeFileSync(join(output, "cli-denied.json"), denied.stdout);
      writeFileSync(join(output, "cli-denied.stderr.log"), denied.stderr);
      const refusal = JSON.parse(denied.stdout || "null");
      check("cli-ungranted-job-denied", denied.code !== 0 && refusal?.decision === "deny",
        { exitCode: denied.code, decision: refusal?.decision, reasonCode: refusal?.reasonCode });
      const reads = controller.requests.filter((request) => request.url.startsWith("/team-ci/"));
      writeFileSync(join(output, "controller-requests.json"), `${JSON.stringify(controller.requests.map((request) => ({
        method: request.method, url: request.url, authorization: request.authorization === expectedAuthorization ? "expected-basic" : request.authorization ? "unexpected" : "absent",
      })), null, 2)}\n`);
      check("controller-saw-one-authorized-read", reads.length === 1 && reads[0].method === "GET"
        && new URL(reads[0].url, "http://controller.invalid").pathname === "/team-ci/job/payments/job/build-api/42/consoleText"
        && reads[0].authorization === expectedAuthorization, { requests: reads.length });

      if (platform === "win32") {
        broker.kill();
        stopped = await waitForExit(broker, SHUTDOWN_TIMEOUT_MS);
        result.shutdown = "forced; POSIX signals are not available on Windows";
      } else {
        broker.kill("SIGTERM");
        stopped = await waitForExit(broker, SHUTDOWN_TIMEOUT_MS);
        check("sigterm-clean-exit", stopped && broker.exitCode === 0, { exitCode: broker.exitCode, signal: broker.signalCode });
        result.shutdown = "SIGTERM, exit 0";
      }
    } finally {
      if (!stopped && broker.exitCode === null && broker.signalCode === null) {
        broker.kill("SIGKILL");
        await waitForExit(broker, SHUTDOWN_TIMEOUT_MS);
      }
      closeSync(log);
    }
    const auditPath = join(run, "audit.jsonl");
    const audit = existsSync(auditPath) ? readFileSync(auditPath, "utf8") : "";
    writeFileSync(join(output, "audit.jsonl"), audit);
    const records = audit.split("\n").filter(Boolean).map((line) => JSON.parse(line))
      .filter((record) => record.service === "cloudbees_ci" && record.action === "build.log.read");
    check("audit-records", records.some((record) => record.decision === "allow") && records.some((record) => record.decision === "deny"),
      { decisions: records.map((record) => record.decision) });
  } finally {
    await controller.close();
  }
  return result;
}

export async function runDownstreamConsumer({ root = ROOT, commit, evidenceDir, cli, source = "staged", env = process.env,
  platform = process.platform } = {}) {
  const evidence = qualificationOutputDirectory(root, evidenceDir);
  mkdirSync(join(evidence, "logs"), { recursive: true, mode: 0o700 });
  const report = { schemaVersion: 1, status: "running", mode: source, commit, startedAt: stamp(), finishedAt: null, steps: [],
    scope: "Independent provider repository and downstream assembly staged from one clean candidate commit; locked offline Cargo against the shared download cache; process acceptance of the assembled broker with a freshly built CLI.",
    limitations: [
      "Host test support is not available yet; process acceptance starts the built assembly executable directly.",
      "Assembly identity covers name and version only; the qualification label and module provenance map are not checked yet.",
      "Portal assets are not served or checked by this fixture.",
      ...(source === "staged" ? ["Upstream is a staged local clone; the canonical remote pin needs a separate --source canonical run after publication."] : []),
      ...(platform === "win32" ? ["Graceful POSIX-signal shutdown is not exercised on Windows."] : []),
    ] };
  const save = () => writeFileSync(join(evidence, "status.json"), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  save();
  let stage = null;
  let logIndex = 0;
  const paths = {};
  const step = async (id, action) => {
    const record = { id, status: "running", startedAt: stamp(), finishedAt: null };
    report.steps.push(record);
    save();
    console.log(`Downstream consumer: ${id}`);
    try {
      const value = await action(record);
      record.status = "passed";
      return value;
    } catch (error) {
      record.status = "failed";
      record.error = error.message;
      throw error;
    } finally {
      record.finishedAt = stamp();
      save();
    }
  };
  const execute = (label, program, args, { cwd, env: commandEnv, input, captureOutput = false }) => {
    logIndex += 1;
    const name = `${String(logIndex).padStart(2, "0")}-${label}.log`;
    const log = openSync(join(evidence, "logs", name), "w", 0o600);
    try {
      writeSync(log, `$ ${[program, ...args].join(" ")}\n# cwd: ${cwd}\n# started: ${stamp()}\n`);
      const result = spawnSync(program, args, { cwd, env: commandEnv, input,
        stdio: [input === undefined ? "ignore" : "pipe", captureOutput ? "pipe" : log, log], maxBuffer: 1024 * 1024 * 1024 });
      writeSync(log, `\n# exit: ${result.status ?? result.signal} ${stamp()}\n`);
      if (result.error) throw result.error;
      if (result.status !== 0) throw new Error(`${label} failed with exit ${result.status ?? result.signal}; see logs/${name}`);
      return captureOutput ? result.stdout : null;
    } finally {
      closeSync(log);
    }
  };
  try {
    const { env: clean, removed } = sanitizedEnvironment(env);
    const sharedCargoHome = resolve(env.CARGO_HOME || join(homedir(), ".cargo"));
    const gitEnv = { ...clean, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: devNull, GIT_TERMINAL_PROMPT: "0" };
    const git = (label, cwd, args, options = {}) => execute(label, "git", args, { cwd, env: gitEnv, ...options });
    const gitText = (cwd, args) => execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    let toolchain;
    let candidateLockText;
    let candidateRootText;
    let upstreamSourceUrl;

    await step("preflight", (record) => {
      assertNoGitOverrides(env);
      assertQualificationSource(root, commit, clean);
      accessSync(cli, constants.X_OK);
      const cliBytes = readFileSync(cli);
      toolchain = inspectLocalToolchain(root, { env: clean });
      report.toolchain = { pinned: toolchain.pinned, host: toolchain.host, cargoPath: toolchain.cargoPath,
        rustcPath: toolchain.rustcPath, cargoVersion: toolchain.cargoVersion, rustcVersion: toolchain.rustcVerbose.split("\n")[0] };
      report.cli = { path: cli, sha256: sha256(cliBytes), bytes: cliBytes.length };
      report.removedEnvironment = removed;
      report.sharedCargoHome = sharedCargoHome;
      record.detail = { root, commit };
    });

    await step("stage-upstream", () => {
      stage = realpathSync(mkdtempSync(join(tmpdir(), "aab-downstream-")));
      chmodSync(stage, 0o700);
      if (isInside(realpathSync(root), stage)) throw new Error("The stage must be outside the candidate checkout; set TMPDIR elsewhere");
      Object.assign(paths, { upstream: join(stage, "upstream"), provider: join(stage, "provider"), assembly: join(stage, "assembly"),
        registry: join(stage, "registry"), cargoHome: join(stage, "cargo-home"), run: join(stage, "run") });
      report.stage = { path: stage, deleted: false };
      git("clone-upstream", stage, ["clone", "--bare", "--no-local", "--no-hardlinks", "--quiet", root, paths.upstream]);
      if (existsSync(join(paths.upstream, "objects", "info", "alternates"))) {
        throw new Error("The staged upstream clone must not borrow objects through alternates");
      }
      if (gitText(paths.upstream, ["rev-parse", "--verify", `${commit}^{commit}`]) !== commit) {
        throw new Error("The staged upstream clone does not contain the candidate commit");
      }
      git("detach-upstream", paths.upstream, ["update-ref", "--no-deref", "HEAD", commit]);
      const refs = gitText(paths.upstream, ["for-each-ref", "--format=%(refname)"]).split("\n").filter(Boolean);
      if (refs.length) {
        git("prune-upstream-refs", paths.upstream, ["update-ref", "--stdin"], { input: refs.map((ref) => `delete ${ref}\n`).join("") });
      }
      git("advertise-candidate", paths.upstream, ["update-ref", "refs/heads/candidate", commit]);
      git("remove-origin", paths.upstream, ["remote", "remove", "origin"]);
      const advertised = gitText(paths.upstream, ["ls-remote", "."]).split("\n").filter(Boolean);
      if (!advertised.length || advertised.some((line) => !line.startsWith(`${commit}\t`))) {
        throw new Error(`The staged upstream must advertise only the candidate commit: ${advertised.join("; ")}`);
      }
      report.upstream = { advertisedRefs: advertised.map((line) => line.split("\t")[1]),
        committedAt: gitText(paths.upstream, ["log", "-1", "--format=%cI", commit]) };
      candidateLockText = gitText(paths.upstream, ["show", `${commit}:Cargo.lock`]) + "\n";
      candidateRootText = gitText(paths.upstream, ["show", `${commit}:Cargo.toml`]) + "\n";
      upstreamSourceUrl = source === "canonical" ? CANONICAL_UPSTREAM_URL : pathToFileURL(paths.upstream).href;
    });

    const candidateLock = parseLockfile(candidateLockText);
    const upstreamNames = new Set(candidateLock.packages.filter((entry) => entry.source === null).map((entry) => entry.name));
    for (const name of [SDK_PACKAGE, PROVIDER_PACKAGE, "agent-access-broker-host", "agent-access-cloudbees-ci"]) {
      if (!upstreamNames.has(name)) throw new Error(`The candidate workspace has no ${name} package`);
    }
    const seed = thirdPartyLockSeed(candidateLockText);

    await step("registry-source", (record) => {
      const cacheRoot = join(sharedCargoHome, "registry", "cache");
      const cacheDirectories = existsSync(cacheRoot) ? readdirSync(cacheRoot, { withFileTypes: true })
        .filter((entry) => entry.isDirectory()).map((entry) => join(cacheRoot, entry.name)) : [];
      const crates = candidateLock.packages.filter((entry) => entry.source === CRATES_IO_SOURCE);
      const missing = [];
      const archives = [];
      for (const entry of crates) {
        const file = `${entry.name}-${entry.version}.crate`;
        const found = cacheDirectories.map((directory) => join(directory, file))
          .find((candidate) => existsSync(candidate) && sha256(readFileSync(candidate)) === entry.checksum);
        if (found) archives.push({ entry, file: found });
        else missing.push(`${entry.name} ${entry.version}`);
      }
      if (missing.length) {
        throw new Error(`${missing.length} locked crates are missing from the shared Cargo download cache under ${cacheRoot} `
          + `(or differ from Cargo.lock); this check never downloads them. Populate the cache with \`cargo fetch --locked\` `
          + `in the candidate checkout first. Missing: ${missing.slice(0, 20).join(", ")}${missing.length > 20 ? ", ..." : ""}`);
      }
      mkdirSync(paths.registry, { mode: 0o700 });
      for (const { entry, file } of archives) {
        const directory = `${entry.name}-${entry.version}`;
        const extraction = mkdtempSync(join(paths.registry, ".extract-"));
        const unpacked = spawnSync("tar", ["-xzf", file, "-C", extraction], { env: clean, encoding: "utf8", stdio: ["ignore", "ignore", "pipe"] });
        if (unpacked.error || unpacked.status !== 0) {
          throw new Error(`Extracting ${file} failed: ${unpacked.error?.message ?? unpacked.stderr.trim()}`);
        }
        const extracted = readdirSync(extraction);
        if (extracted.length !== 1 || extracted[0] !== directory) {
          throw new Error(`${file} must contain only ${directory}/`);
        }
        renameSync(join(extraction, directory), join(paths.registry, directory));
        rmSync(extraction, { recursive: true });
        writeFileSync(join(paths.registry, directory, ".cargo-checksum.json"), JSON.stringify({ files: {}, package: entry.checksum }));
      }
      mkdirSync(paths.cargoHome, { mode: 0o700 });
      const config = `# Private Cargo home for the staged repositories. crates.io packages
# resolve only from archives copied out of the shared download cache.
[source.crates-io]
replace-with = "shared-download-cache"

[source.shared-download-cache]
directory = ${JSON.stringify(paths.registry)}
`;
      writeFileSync(join(paths.cargoHome, "config.toml"), config, { mode: 0o600 });
      writeFileSync(join(evidence, "cargo-home-config.toml"), config);
      record.detail = { crates: archives.length, cacheDirectories };
      report.registry = { replacement: "directory source built from the shared download cache", crates: archives.length, cacheDirectories };
      // Ambient configuration in an ancestor directory still applies to the
      // staged repositories; reject any that could change dependency sources.
      const configs = [...new Map([paths.provider, paths.assembly]
        .flatMap((directory) => cargoConfigInventory(directory, { CARGO_HOME: paths.cargoHome }))
        .map((config) => [config.path, config])).values()];
      report.cargoConfigs = configs;
      const foreign = configs.filter((config) => config.path !== join(paths.cargoHome, "config.toml")
        && /^\s*\[(?:source|patch|registries|registry)\b/m.test(readFileSync(config.path, "utf8")));
      if (foreign.length) throw new Error(`Ambient Cargo configuration changes dependency sources: ${foreign.map((config) => config.path).join(", ")}`);
    });

    const rustdoc = realpathSync(join(dirname(toolchain.rustcPath), process.platform === "win32" ? "rustdoc.exe" : "rustdoc"));
    const rustfmt = realpathSync(join(dirname(toolchain.rustcPath), process.platform === "win32" ? "rustfmt.exe" : "rustfmt"));
    const cargoEnv = { ...clean, CARGO_HOME: paths.cargoHome, RUSTC: toolchain.rustcPath, RUSTDOC: rustdoc, CARGO_TERM_COLOR: "never" };
    const cargo = (label, cwd, args, options = {}) => execute(label, toolchain.cargoPath, args, { cwd, env: cargoEnv, ...options });
    const extract = (label, path, destination, strip) => {
      const archive = execFileSync("git", ["archive", "--format=tar", commit, "--", path],
        { cwd: paths.upstream, env: gitEnv, maxBuffer: 1024 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
      execute(label, "tar", ["-x", "-C", destination, ...(strip ? [`--strip-components=${strip}`] : [])], { cwd: destination, env: clean, input: archive });
    };
    const commitRepository = (label, directory, message) => {
      const identity = { GIT_AUTHOR_NAME: "Downstream Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid",
        GIT_COMMITTER_NAME: "Downstream Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid",
        GIT_AUTHOR_DATE: report.upstream.committedAt, GIT_COMMITTER_DATE: report.upstream.committedAt };
      git(`${label}-init`, directory, ["init", "--quiet", "--initial-branch=main"]);
      git(`${label}-add`, directory, ["add", "--all"]);
      execute(`${label}-commit`, "git", ["commit", "--quiet", "--no-verify", "-m", message], { cwd: directory, env: { ...gitEnv, ...identity } });
      return gitText(directory, ["rev-parse", "HEAD"]);
    };
    const assertToolchain = (directory) => {
      const channel = toolchainChannel(readFileSync(join(directory, "rust-toolchain.toml"), "utf8"));
      if (channel !== toolchain.pinned) throw new Error(`${directory} pins ${channel}; the candidate pins ${toolchain.pinned}`);
    };
    const upstreamSource = { canonical: CANONICAL_UPSTREAM_URL, url: upstreamSourceUrl, rev: commit, packages: upstreamNames };
    const mapping = { schemaVersion: 1, mode: source, candidate: { commit, committedAt: report.upstream.committedAt },
      sources: [], manifests: [] };
    let providerCommit;

    await step("stage-provider", (record) => {
      mkdirSync(paths.provider, { mode: 0o700 });
      extract("archive-provider-template", `${FIXTURE_DIRECTORY}/provider-repo`, paths.provider, 3);
      extract("archive-provider-crate", PROVIDER_CRATE_DIRECTORY, paths.provider, 0);
      assertToolchain(paths.provider);
      const crateManifestPath = join(paths.provider, PROVIDER_CRATE_DIRECTORY, "Cargo.toml");
      const crateManifest = readFileSync(crateManifestPath, "utf8");
      if (/^name = "([^"]+)"$/m.exec(crateManifest)?.[1] !== PROVIDER_PACKAGE) {
        throw new Error(`${PROVIDER_CRATE_DIRECTORY} must define package ${PROVIDER_PACKAGE}`);
      }
      const normalized = normalizeProviderCrateManifest(crateManifest);
      const rootPath = join(paths.provider, "Cargo.toml");
      const template = readFileSync(rootPath, "utf8");
      if (lastTableHeader(template) !== "workspace.dependencies") {
        throw new Error("The provider template must end with its [workspace.dependencies] table");
      }
      const inherited = inheritedWorkspaceDependencies(candidateRootText, normalized.inherited);
      const sources = [upstreamSource];
      const rootManifest = rewriteStagedManifest(`${template.trimEnd()}\n${inherited.join("\n")}\n`, sources);
      const crate = rewriteStagedManifest(normalized.text, sources);
      writeFileSync(rootPath, rootManifest.text);
      writeFileSync(crateManifestPath, crate.text);
      writeFileSync(join(paths.provider, "Cargo.lock"), seed);
      mapping.manifests.push({ repository: "provider", path: "Cargo.toml", rewrites: rootManifest.rewrites, inheritedFromCandidate: normalized.inherited },
        { repository: "provider", path: `${PROVIDER_CRATE_DIRECTORY}/Cargo.toml`, rewrites: crate.rewrites,
          normalized: `${SDK_PACKAGE} path dependency replaced by the provider workspace pin` });
      cargo("provider-setup-fetch", paths.provider, ["fetch"]);
      providerCommit = commitRepository("provider", paths.provider,
        `Provider repository staged from ${commit}\n\nContains ${PROVIDER_CRATE_DIRECTORY} and ${FIXTURE_DIRECTORY}/provider-repo.`);
      record.detail = { commit: providerCommit };
    });

    const providerSourceUrl = pathToFileURL(paths.provider).href;
    let assemblyCommit;
    await step("stage-assembly", (record) => {
      mkdirSync(paths.assembly, { mode: 0o700 });
      extract("archive-assembly-template", `${FIXTURE_DIRECTORY}/assembly-repo`, paths.assembly, 3);
      assertToolchain(paths.assembly);
      const manifestPath = join(paths.assembly, "Cargo.toml");
      const sources = [
        { canonical: CANONICAL_PROVIDER_URL, url: providerSourceUrl, rev: providerCommit, packages: new Set([PROVIDER_PACKAGE]) },
        upstreamSource,
      ];
      const manifest = rewriteStagedManifest(readFileSync(manifestPath, "utf8"), sources);
      writeFileSync(manifestPath, manifest.text);
      writeFileSync(join(paths.assembly, "Cargo.lock"), seed);
      mapping.manifests.push({ repository: "assembly", path: "Cargo.toml", rewrites: manifest.rewrites });
      cargo("assembly-setup-fetch", paths.assembly, ["fetch"]);
      assemblyCommit = commitRepository("assembly", paths.assembly, `Downstream assembly staged from ${commit}`);
      record.detail = { commit: assemblyCommit };
    });

    mapping.sources.push(
      { role: "upstream", canonical: { git: CANONICAL_UPSTREAM_URL, rev: SENTINEL_REV }, staged: { git: upstreamSourceUrl, rev: commit },
        lockSource: gitSourceId(upstreamSourceUrl, commit), advertisedRefs: report.upstream.advertisedRefs },
      { role: "provider", canonical: { git: CANONICAL_PROVIDER_URL, rev: SENTINEL_REV }, staged: { git: providerSourceUrl, rev: providerCommit },
        lockSource: gitSourceId(providerSourceUrl, providerCommit),
        contents: [`${PROVIDER_CRATE_DIRECTORY} at ${commit}`, `${FIXTURE_DIRECTORY}/provider-repo at ${commit}`] },
      { role: "assembly", repository: "local only", commit: assemblyCommit, contents: [`${FIXTURE_DIRECTORY}/assembly-repo at ${commit}`] },
    );
    mapping.registry = report.registry;
    writeFileSync(join(evidence, "source-mapping.json"), `${JSON.stringify(mapping, null, 2)}\n`);

    await step("lock-review", (record) => {
      const review = reviewLockfiles({ candidate: candidateLock,
        staged: [
          { repository: "provider", lock: parseLockfile(readFileSync(join(paths.provider, "Cargo.lock"), "utf8")), members: [PROVIDER_PACKAGE] },
          { repository: "assembly", lock: parseLockfile(readFileSync(join(paths.assembly, "Cargo.lock"), "utf8")), members: [ASSEMBLY_PACKAGE] },
        ],
        upstreamSource: gitSourceId(upstreamSourceUrl, commit), providerSource: gitSourceId(providerSourceUrl, providerCommit) });
      writeFileSync(join(evidence, "lock-review.json"), `${JSON.stringify(review, null, 2)}\n`);
      record.detail = { summary: review.summary, sdkPackageIds: review.sdkPackageIds };
      if (review.errors.length) throw new Error(`Lockfile review failed:\n${review.errors.join("\n")}`);
    });

    await step("provider-tests", () => {
      cargo("provider-test", paths.provider, ["test", "--locked", "--offline"]);
    });

    await step("provider-boundaries", (record) => {
      const metadata = JSON.parse(cargo("provider-metadata", paths.provider,
        ["metadata", "--locked", "--offline", "--format-version", "1"], { captureOutput: true }).toString("utf8"));
      const tree = cargo("provider-tree", paths.provider,
        ["tree", "--locked", "--offline", "-e", "normal,build,dev,features", "--target", "all"], { captureOutput: true }).toString("utf8");
      writeFileSync(join(evidence, "cargo-tree-provider.txt"), tree);
      const violations = providerBoundaryViolations(metadata);
      record.detail = { packages: metadata.packages.length };
      if (violations.length) throw new Error(`The provider repository reaches forbidden upstream crates:\n${violations.join("\n")}`);
    });

    const binary = join(paths.assembly, "target", "debug", platform === "win32" ? `${ASSEMBLY_PACKAGE}.exe` : ASSEMBLY_PACKAGE);
    await step("assembly-build", () => {
      execute("assembly-format", rustfmt, ["--check", "--edition", ASSEMBLY_EDITION, "src/lib.rs", "src/main.rs"],
        { cwd: paths.assembly, env: cargoEnv });
      cargo("assembly-build", paths.assembly, ["build", "--locked", "--offline"]);
      cargo("assembly-test", paths.assembly, ["test", "--locked", "--offline"]);
      accessSync(binary, constants.X_OK);
    });

    await step("assembly-features", (record) => {
      const tree = cargo("assembly-tree", paths.assembly, ["tree", "--locked", "--offline", "-e", "normal,build,features",
        "--target", "all", "-p", ASSEMBLY_PACKAGE], { captureOutput: true }).toString("utf8");
      writeFileSync(join(evidence, "cargo-tree-assembly.txt"), tree);
      const violations = featureViolations(tree);
      record.detail = { lines: tree.split("\n").length };
      if (violations.length) throw new Error(`The assembly release graph enables test support:\n${violations.join("\n")}`);
    });

    await step("process-acceptance", async (record) => {
      report.acceptance = await processAcceptance({ binary, cli, run: paths.run, evidence, env: clean,
        version: /^version = "([^"]+)"$/m.exec(readFileSync(join(paths.assembly, "Cargo.toml"), "utf8"))[1], platform });
      record.detail = { checks: report.acceptance.checks.length, shutdown: report.acceptance.shutdown };
    });

    assertQualificationSource(root, commit, clean);
    report.status = "passed";
  } catch (error) {
    report.status = "failed";
    report.error = error.message;
    throw error;
  } finally {
    try {
      for (const [repository, files] of [["provider", ["Cargo.lock", "Cargo.toml", `${PROVIDER_CRATE_DIRECTORY}/Cargo.toml`]],
        ["assembly", ["Cargo.lock", "Cargo.toml"]]]) {
        for (const file of files) {
          const from = paths[repository] && join(paths[repository], file);
          if (from && existsSync(from)) {
            const to = join(evidence, "staged", repository, file);
            mkdirSync(dirname(to), { recursive: true });
            copyFileSync(from, to);
          }
        }
      }
    } finally {
      if (stage) {
        rmSync(stage, { recursive: true, force: true });
        report.stage.deleted = !existsSync(stage);
      }
      report.finishedAt = stamp();
      save();
    }
  }
  console.log(`Downstream consumer passed at ${commit}: ${join(evidence, "status.json")}`);
  return report;
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH)) {
  try {
    await runDownstreamConsumer(parseConsumerArguments(process.argv.slice(2)));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
