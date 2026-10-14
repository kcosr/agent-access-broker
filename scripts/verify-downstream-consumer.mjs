#!/usr/bin/env node
// Stage an independent provider repository and a downstream broker assembly
// from one clean candidate commit, build them and the candidate's CLI with
// locked offline Cargo against the shared download cache, and run the
// assembled broker. See tests/downstream-consumer/README.md. This command
// never publishes.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { accessSync, chmodSync, closeSync, constants, copyFileSync, existsSync, mkdirSync, mkdtempSync,
  openSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { constants as osConstants, devNull, homedir, tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { assertNoGitOverrides } from "./release-environment.mjs";
import { assertQualificationSource, qualificationOutputDirectory } from "./verify-release.mjs";
import { cargoConfigInventory, inspectLocalToolchain, parseCargoTree } from "./verify-release-provenance.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const ROOT = resolve(dirname(SCRIPT_PATH), "..");

export const CANONICAL_UPSTREAM_URL = "https://github.com/kcosr/agent-access-broker.git";
export const CANONICAL_PROVIDER_URL = "https://git.example.com/provider-team/conformance-provider.git";
export const SENTINEL_REV = "0".repeat(40);
export const CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index";
export const SDK_PACKAGE = "agent-access-provider";
export const PROVIDER_PACKAGE = "agent-access-conformance";
export const ASSEMBLY_PACKAGE = "downstream-broker";
const CLI_PACKAGE = "agent-access";
const PROVIDER_CRATE_DIRECTORY = "crates/agent-access-conformance";
const FIXTURE_DIRECTORY = "tests/downstream-consumer";
const FULL_SHA1 = /^[0-9a-f]{40}$/;
// Roles a reference provider repository must not reach through any edge.
const FORBIDDEN_PROVIDER_ROLES = Object.freeze(["core", "host", "assembly", "cli", "adapter"]);
const ASSEMBLY_EDITION = "2024";
const HOST_PACKAGE = "agent-access-broker-host";
const CLOUDBEES_PACKAGE = "agent-access-cloudbees-ci";
// The label this driver declares for the assembly it builds and qualifies.
export const FIXTURE_QUALIFICATION = "downstream-consumer";
const INVENTORY_FINGERPRINT_DOMAIN = "agent-access.broker.inventory.v1";
const SYNTHETIC_LOG = "downstream consumer log line\n";
const READY_TIMEOUT_MS = 60_000;
const PROCESS_TIMEOUT_MS = 60_000;
const SHUTDOWN_TIMEOUT_MS = 30_000;
const stamp = () => new Date().toISOString();
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const delay = (milliseconds) => new Promise((done) => setTimeout(done, milliseconds));

const USAGE = "Usage: node scripts/verify-downstream-consumer.mjs --commit <full-sha> "
  + "--evidence-dir /absolute/new/directory [--source staged|canonical]";

export function parseConsumerArguments(args) {
  const keys = { "--commit": "commit", "--evidence-dir": "evidenceDir", "--source": "source" };
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = keys[args[index]];
    if (!key || Object.hasOwn(options, key) || index + 1 >= args.length) throw new Error(USAGE);
    options[key] = args[index + 1];
  }
  options.source ??= "staged";
  if (!FULL_SHA1.test(options.commit ?? "") || !isAbsolute(options.evidenceDir ?? "")
      || !["staged", "canonical"].includes(options.source)) {
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

// Resolves features for the normal and build units of the assembly built for
// `target`: without dev edges Cargo resolves no dev units. `{f}` is each
// unit's resolved feature set, including features a root's defaults enable
// that a feature-edge traversal does not display.
export function assemblyFeatureTreeArgs(target) {
  return ["tree", "--locked", "--offline", "--target", target, "-p", ASSEMBLY_PACKAGE,
    "-e", "normal,build", "--prefix", "none", "--format", "{p}\t{f}"];
}

// Packages whose resolved release feature set includes test support, from
// `assemblyFeatureTreeArgs` output parsed as the upstream release verifier does.
export function assemblyFeatureViolations(output) {
  const packages = parseCargoTree(output);
  if (!packages.some((entry) => entry.name === ASSEMBLY_PACKAGE)) {
    throw new Error(`cargo tree output omits the assembly package ${ASSEMBLY_PACKAGE}`);
  }
  return packages.filter((entry) => entry.features.includes("test-support"))
    .map((entry) => `${entry.name} ${entry.version}${entry.source ? ` (${entry.source})` : ""} enables test-support`);
}

export function providerBoundaryViolations(metadata) {
  return (metadata.packages ?? []).filter((entry) => FORBIDDEN_PROVIDER_ROLES.includes(entry.metadata?.["agent-access"]?.role))
    .map((entry) => `${entry.name} ${entry.version} (${entry.metadata["agent-access"].role}) is in the provider repository graph`);
}

// The host's inventory fingerprint, recomputed: SHA-256 over a
// length-delimited encoding of the host and SDK packages and the module
// inventory, each with its source revision and provenance.
export function inventoryFingerprint({ host, sdk, modules }) {
  const parts = [];
  const count = (value) => {
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64BE(BigInt(value));
    parts.push(bytes);
  };
  const string = (value) => {
    const bytes = Buffer.from(value, "utf8");
    count(bytes.length);
    parts.push(bytes);
  };
  const source = ({ provenance, revision }) => {
    string(provenance);
    string(revision ?? "");
  };
  string(INVENTORY_FINGERPRINT_DOMAIN);
  for (const [label, entry] of [["host", host], ["sdk", sdk]]) {
    string(label);
    string(entry.crate);
    string(entry.version);
    source(entry.source);
  }
  count(modules.length);
  for (const module of modules) {
    string(module.crate);
    string(module.version);
    count(module.roles.length);
    for (const role of module.roles) {
      string(role.role);
      string(role.id);
    }
    source(module.source);
  }
  return `sha256:${sha256(Buffer.concat(parts))}`;
}

// The identity part of the status an assembly built from the given sources
// must report: every revision evidence-backed and the modules in canonical
// order.
export function expectedAssemblyStatus({ assembly, host, sdk, modules }) {
  const evidence = (revision) => ({ revision, provenance: "evidence" });
  const status = {
    assembly: { name: assembly.name, version: assembly.version, qualification: assembly.qualification,
      source: evidence(assembly.revision) },
    host: { crate: HOST_PACKAGE, version: host.version, source: evidence(host.revision) },
    sdk: { crate: SDK_PACKAGE, version: sdk.version, source: evidence(sdk.revision) },
    modules: [...modules].sort((left, right) => left.crate.localeCompare(right.crate) || left.version.localeCompare(right.version))
      .map((module) => ({ crate: module.crate, version: module.version, roles: module.roles, source: evidence(module.revision) })),
  };
  status.inventoryFingerprint = inventoryFingerprint(status);
  return status;
}

export function assertAssemblyStatus(status, expected) {
  const { catalogVersion, sendSchemaVersion, ...identity } = status ?? {};
  if (!isDeepStrictEqual(identity, expected) || typeof catalogVersion !== "string" || typeof sendSchemaVersion !== "string") {
    throw new Error(`Status must report the assembly's identity, locked sources and inventory fingerprint; expected ${JSON.stringify(expected)}, received ${JSON.stringify(status)}`);
  }
}

// The broker_starting event must carry the same assembly identity and
// inventory fingerprint as the status.
export function assertStartingEvent(log, status) {
  const events = log.split("\n").filter(Boolean).map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  }).filter((event) => event?.event === "broker_starting");
  const expected = { assemblyName: status.assembly.name, assemblyVersion: status.assembly.version,
    assemblyRevision: status.assembly.source.revision, assemblyProvenance: status.assembly.source.provenance,
    qualification: status.assembly.qualification, inventoryFingerprint: status.inventoryFingerprint };
  if (events.length !== 1 || Object.entries(expected).some(([field, value]) => events[0][field] !== value)) {
    throw new Error(`Exactly one broker_starting event must carry ${JSON.stringify(expected)}; found ${JSON.stringify(events)}`);
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

// Isolates Git for the driver's Git commands and for Cargo's Git fetches,
// which the staged Cargo configuration routes through the Git CLI: no system
// or global configuration (so no URL rewrites or credential helpers), an empty
// stage-owned home, and only the listed transports.
export function isolatedGitEnvironment(env, { home, protocols }) {
  return { ...env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: devNull, GIT_TERMINAL_PROMPT: "0", GIT_ALLOW_PROTOCOL: protocols };
}

export function stagedCargoConfig(registryDirectory) {
  return `# Private Cargo home for the staged repositories. crates.io packages
# resolve only from archives copied out of the shared download cache; Git
# dependencies are fetched by the isolated Git CLI.
[source.crates-io]
replace-with = "shared-download-cache"

[source.shared-download-cache]
directory = ${JSON.stringify(registryDirectory)}

[net]
git-fetch-with-cli = true
`;
}

// Every Cargo configuration file that applies to Cargo run in `directory`
// besides the private one. Any such file is rejected rather than inspected:
// directly or through includes it could replace sources, patch dependencies,
// redirect artifacts or install runners.
export function foreignCargoConfigs(directory, cargoHome) {
  const own = join(cargoHome, "config.toml");
  return cargoConfigInventory(directory, { CARGO_HOME: cargoHome }).filter((config) => config.path !== own);
}

export class InterruptedError extends Error {
  constructor(signal) {
    super(`Interrupted by ${signal}`);
    this.name = "InterruptedError";
    this.signal = signal;
  }
}

// Whether a process group still has a live member. On Linux exited but
// unreaped descendants (zombies) do not count; elsewhere any member counts.
export function processGroupAlive(pgid) {
  try {
    process.kill(-pgid, 0);
  } catch (error) {
    if (error.code === "ESRCH") return false;
    throw error;
  }
  if (process.platform !== "linux") return true;
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    let stat;
    try {
      stat = readFileSync(`/proc/${entry}/stat`, "utf8");
    } catch {
      continue;
    }
    const [state, , group] = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    if (Number(group) === pgid && state !== "Z" && state !== "X") return true;
  }
  return false;
}

// Owns every process the driver starts. On POSIX each child leads its own
// process group, so termination reaches whole trees such as Cargo and its
// compiler processes. A record stays owned until its leader has exited and
// its group has no live member; descendants that outlive their leader are
// stopped then. Processes that leave the group (setsid) are not tracked.
// Once interrupted, no new process starts.
export class ProcessSupervisor {
  #records = new Set();
  #strays = [];
  #interruption = null;
  #platform;
  #graceMs;

  constructor({ platform = process.platform, graceMs = 5_000 } = {}) {
    this.#platform = platform;
    this.#graceMs = graceMs;
  }

  get interruption() {
    return this.#interruption?.signal ?? null;
  }

  // Process groups whose leader exited while descendants were still running.
  get strays() {
    return this.#strays.map((stray) => ({ ...stray }));
  }

  assertRunning() {
    if (this.#interruption) throw new InterruptedError(this.#interruption.signal);
  }

  start(command, args, { cwd, env, stdio = ["ignore", "ignore", "ignore"] } = {}) {
    this.assertRunning();
    const child = spawn(command, args, { cwd, env, stdio, detached: this.#platform !== "win32" });
    const record = { child, command, finished: false, released: false };
    record.closed = new Promise((resolvePromise) => {
      child.once("error", (error) => resolvePromise({ code: null, signal: null, error }));
      child.once("close", (code, signal) => resolvePromise({ code, signal, error: null }));
    }).then((result) => {
      record.finished = true;
      return result;
    });
    this.#records.add(record);
    return record;
  }

  // Runs one command to completion, including any descendants left in its
  // process group. `stdout`/`stderr` take "ignore", "pipe" (collected and
  // returned) or an open file descriptor.
  async run(command, args, { cwd, env, input, stdout = "ignore", stderr = "ignore", timeoutMs } = {}) {
    const record = this.start(command, args, { cwd, env, stdio: [input === undefined ? "ignore" : "pipe", stdout, stderr] });
    const output = { stdout: [], stderr: [] };
    record.child.stdout?.on("data", (chunk) => output.stdout.push(chunk));
    record.child.stderr?.on("data", (chunk) => output.stderr.push(chunk));
    if (input !== undefined) {
      record.child.stdin.on("error", () => {});
      record.child.stdin.end(input);
    }
    let termination = null;
    const timer = timeoutMs ? setTimeout(() => { termination = this.terminate(record); }, timeoutMs) : null;
    const result = await record.closed;
    clearTimeout(timer);
    await (termination ?? this.release(record));
    this.assertRunning();
    return { ...result, timedOut: termination !== null, stdout: Buffer.concat(output.stdout), stderr: Buffer.concat(output.stderr) };
  }

  #groupAlive(record) {
    const { pid } = record.child;
    if (pid === undefined) return false;
    return this.#platform === "win32" ? !record.finished : processGroupAlive(pid);
  }

  #signal(record, signal) {
    const { pid } = record.child;
    if (pid === undefined) return false;
    try {
      if (this.#platform === "win32") return record.child.kill(signal);
      process.kill(-pid, signal);
      return true;
    } catch (error) {
      if (error.code === "ESRCH") return false;
      throw error;
    }
  }

  async #waitForEmptyGroup(record, milliseconds) {
    const deadline = Date.now() + milliseconds;
    while (this.#groupAlive(record)) {
      if (Date.now() >= deadline) return false;
      await delay(50);
    }
    return true;
  }

  // Stops what remains of a group whose leader has exited.
  async #stopGroup(record) {
    if (!this.#groupAlive(record)) return;
    this.#signal(record, "SIGTERM");
    if (await this.#waitForEmptyGroup(record, this.#graceMs)) return;
    this.#signal(record, "SIGKILL");
    if (!(await this.#waitForEmptyGroup(record, this.#graceMs))) {
      throw new Error(`Process group ${record.child.pid} of ${record.command} still has live members after SIGKILL`);
    }
  }

  // Waits for the leader, stops descendants it left running, and releases
  // ownership of the group.
  async release(record) {
    await record.closed;
    if (!record.released && this.#groupAlive(record)) {
      this.#strays.push({ command: record.command, processGroup: record.child.pid });
      await this.#stopGroup(record);
    }
    record.released = true;
    this.#records.delete(record);
  }

  // Stops a whole process tree: SIGTERM to its group, SIGKILL to the leader
  // after the grace period, then the same for any descendants that remain.
  async terminate(record) {
    if (record.released) return;
    this.#signal(record, "SIGTERM");
    const stopped = await Promise.race([record.closed.then(() => true), delay(this.#graceMs).then(() => false)]);
    if (!stopped) this.#signal(record, "SIGKILL");
    await record.closed;
    await this.#stopGroup(record);
    record.released = true;
    this.#records.delete(record);
  }

  interrupt(signal) {
    if (!this.#interruption) {
      this.#interruption = { signal, done: Promise.all([...this.#records].map((record) => this.terminate(record))) };
    }
    return this.#interruption.done;
  }

  // Stops every process still owned, including after an interruption.
  async stopAll() {
    const results = await Promise.allSettled([this.#interruption?.done, ...[...this.#records].map((record) => this.terminate(record))]);
    const failure = results.find((result) => result.status === "rejected");
    if (failure) throw failure.reason;
  }
}

export function installInterruptHandlers(supervisor, signals = ["SIGINT", "SIGTERM"]) {
  const handler = (signal) => {
    console.error(`Downstream consumer: ${signal} received; stopping child processes and removing the stage`);
    // Termination failures surface through stopAll() during cleanup.
    supervisor.interrupt(signal).catch(() => {});
  };
  for (const signal of signals) process.on(signal, handler);
  return () => {
    for (const signal of signals) process.off(signal, handler);
  };
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

[limits]
upload_spool_dir = ${JSON.stringify(join(run, "spool"))}

[audit]
type = "jsonl"
path = ${JSON.stringify(join(run, "audit.jsonl"))}
`;
}

export function startSyntheticController() {
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

async function runCaptured(supervisor, command, args, { env, cwd }) {
  const result = await supervisor.run(command, args, { env, cwd, stdout: "pipe", stderr: "pipe", timeoutMs: PROCESS_TIMEOUT_MS });
  if (result.error) throw result.error;
  return { code: result.code, signal: result.signal, timedOut: result.timedOut,
    stdout: result.stdout.toString("utf8"), stderr: result.stderr.toString("utf8") };
}

async function waitForReady(supervisor, url, broker) {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  let last = "no response";
  while (Date.now() < deadline) {
    supervisor.assertRunning();
    if (broker.finished) {
      const exit = await broker.closed;
      throw new Error(`The assembled broker exited before readiness with ${exit.code ?? exit.signal ?? exit.error?.message}`);
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
      last = `HTTP ${response.status}`;
    } catch (error) {
      last = error.message;
    }
    await delay(200);
  }
  throw new Error(`The assembled broker was not ready: ${last}`);
}

// Starts the built assembly against a synthetic CloudBees controller, checks
// readiness, status identity and one read through the CLI, then stops it.
export async function runProcessAcceptance({ supervisor, binary, cli, run, evidence, env, expectedStatus, platform = process.platform }) {
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
  let broker = null;
  try {
    const configPath = join(run, "broker.toml");
    const gatedPath = join(run, "broker-without-development.toml");
    writeFileSync(configPath, brokerConfiguration({ run, port: controller.port, development: true }), { mode: 0o600 });
    writeFileSync(gatedPath, brokerConfiguration({ run, port: controller.port, development: false }), { mode: 0o600 });
    copyFileSync(configPath, join(output, "broker.toml"));

    const gated = await runCaptured(supervisor, binary, ["--config", gatedPath, "config", "validate"], { env, cwd: run });
    writeFileSync(join(output, "config-validate-without-development.log"), `${gated.stdout}${gated.stderr}`);
    check("development-provider-requires-fixtures", gated.code === 3 && gated.stderr.includes("providers.conformance"),
      { exitCode: gated.code });
    const validated = await runCaptured(supervisor, binary, ["--config", configPath, "config", "validate"], { env, cwd: run });
    writeFileSync(join(output, "config-validate.log"), `${validated.stdout}${validated.stderr}`);
    check("config-validate", validated.code === 0, { exitCode: validated.code });

    const port = await freeLoopbackPort();
    const base = `http://127.0.0.1:${port}`;
    const log = openSync(join(output, "broker.log"), "w", 0o600);
    try {
      broker = supervisor.start(binary, ["--config", configPath, "serve", "--listen", `127.0.0.1:${port}`],
        { env, cwd: run, stdio: ["ignore", log, log] });
    } finally {
      closeSync(log);
    }
    await waitForReady(supervisor, `${base}/v1/readyz`, broker);
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
    assertAssemblyStatus(status, expectedStatus);
    check("status-assembly-identity", true, { assembly: status.assembly, inventoryFingerprint: status.inventoryFingerprint });

    const clientConfig = join(run, "client.toml");
    writeFileSync(clientConfig, `[service]\nurl = ${JSON.stringify(base)}\n\n[identity]\nheader = "X-Agent-Access-Identity-Token"\nscheme = "raw"\ntoken_file = ${JSON.stringify(join(run, "principal-token"))}\n`, { mode: 0o600 });
    const invoke = (job) => runCaptured(supervisor, cli, ["--config", clientConfig, "invoke", "cloudbees_ci.build.log.read", "--input-json",
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
      method: request.method, url: request.url,
      authorization: request.authorization === expectedAuthorization ? "expected-basic" : request.authorization ? "unexpected" : "absent",
    })), null, 2)}\n`);
    check("controller-saw-one-authorized-read", reads.length === 1 && reads[0].method === "GET"
      && new URL(reads[0].url, "http://controller.invalid").pathname === "/team-ci/job/payments/job/build-api/42/consoleText"
      && reads[0].authorization === expectedAuthorization, { requests: reads.length });

    if (platform === "win32") {
      await supervisor.terminate(broker);
      result.shutdown = "forced; POSIX signals are not available on Windows";
    } else {
      broker.child.kill("SIGTERM");
      const exit = await Promise.race([broker.closed, delay(SHUTDOWN_TIMEOUT_MS).then(() => null)]);
      supervisor.assertRunning();
      check("sigterm-clean-exit", exit?.code === 0, { exitCode: exit?.code ?? null, signal: exit?.signal ?? null });
      await supervisor.release(broker);
      result.shutdown = "SIGTERM, exit 0";
    }
    assertStartingEvent(readFileSync(join(output, "broker.log"), "utf8"), status);
    check("starting-event-identity", true);
    const auditPath = join(run, "audit.jsonl");
    const audit = existsSync(auditPath) ? readFileSync(auditPath, "utf8") : "";
    writeFileSync(join(output, "audit.jsonl"), audit);
    const records = audit.split("\n").filter(Boolean).map((line) => JSON.parse(line))
      .filter((record) => record.service === "cloudbees_ci" && record.action === "build.log.read");
    check("audit-records", records.some((record) => record.decision === "allow") && records.some((record) => record.decision === "deny"),
      { decisions: records.map((record) => record.decision) });
  } finally {
    if (broker) await supervisor.terminate(broker);
    await controller.close();
  }
  return result;
}

export async function runDownstreamConsumer({ root = ROOT, commit, evidenceDir, source = "staged", env = process.env,
  platform = process.platform, supervisor = new ProcessSupervisor({ platform }) } = {}) {
  const evidence = qualificationOutputDirectory(root, evidenceDir);
  mkdirSync(join(evidence, "logs"), { recursive: true, mode: 0o700 });
  const report = { schemaVersion: 1, status: "running", mode: source, commit, startedAt: stamp(), finishedAt: null, steps: [],
    scope: "Independent provider repository and downstream assembly staged from one clean candidate commit; locked offline Cargo against the shared download cache; process acceptance of the assembled broker with the candidate's CLI built in the stage.",
    limitations: [
      "Portal assets are not served or checked by this fixture.",
      ...(source === "staged" ? ["Upstream is a staged local clone; the canonical remote pin needs a separate --source canonical run after publication."] : []),
      ...(platform === "win32" ? ["Graceful POSIX-signal shutdown and process-group termination are not exercised on Windows."] : []),
    ] };
  const save = () => writeFileSync(join(evidence, "status.json"), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  save();
  const removeHandlers = installInterruptHandlers(supervisor);
  let stage = null;
  let logIndex = 0;
  const paths = {};
  const step = async (id, action) => {
    supervisor.assertRunning();
    const record = { id, status: "running", startedAt: stamp(), finishedAt: null };
    report.steps.push(record);
    save();
    console.log(`Downstream consumer: ${id}`);
    try {
      const value = await action(record);
      supervisor.assertRunning();
      record.status = "passed";
      return value;
    } catch (error) {
      record.status = supervisor.interruption ? "interrupted" : "failed";
      record.error = error.message;
      throw error;
    } finally {
      record.finishedAt = stamp();
      save();
    }
  };
  const execute = async (label, program, args, { cwd, env: commandEnv, input, capture = false }) => {
    logIndex += 1;
    const name = `${String(logIndex).padStart(2, "0")}-${label}.log`;
    const log = openSync(join(evidence, "logs", name), "w", 0o600);
    try {
      writeSync(log, `$ ${[program, ...args].join(" ")}\n# cwd: ${cwd}\n# started: ${stamp()}\n`);
      let result;
      try {
        result = await supervisor.run(program, args, { cwd, env: commandEnv, input, stdout: capture ? "pipe" : log, stderr: log });
      } catch (error) {
        writeSync(log, `\n# ${error.message} ${stamp()}\n`);
        throw error;
      }
      writeSync(log, `\n# exit: ${result.code ?? result.signal} ${stamp()}\n`);
      if (result.error) throw result.error;
      if (result.code !== 0) throw new Error(`${label} failed with exit ${result.code ?? result.signal}; see logs/${name}`);
      return capture ? result.stdout : null;
    } finally {
      closeSync(log);
    }
  };
  const executable = (name) => (platform === "win32" ? `${name}.exe` : name);
  try {
    const { env: clean, removed } = sanitizedEnvironment(env);
    const sharedCargoHome = resolve(env.CARGO_HOME || join(homedir(), ".cargo"));
    let gitEnv;
    let toolchain;
    let candidateLockText;
    let candidateRootText;
    let upstreamSourceUrl;
    const git = (label, cwd, args, options = {}) => execute(label, "git", args, { cwd, env: gitEnv, ...options });
    const gitText = (cwd, args) => execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

    await step("preflight", (record) => {
      assertNoGitOverrides(env);
      assertQualificationSource(root, commit, clean);
      toolchain = inspectLocalToolchain(root, { env: clean });
      report.toolchain = { pinned: toolchain.pinned, host: toolchain.host, cargoPath: toolchain.cargoPath,
        rustcPath: toolchain.rustcPath, cargoVersion: toolchain.cargoVersion, rustcVersion: toolchain.rustcVerbose.split("\n")[0] };
      report.removedEnvironment = removed;
      report.sharedCargoHome = sharedCargoHome;
      record.detail = { root, commit };
    });

    await step("stage-upstream", async () => {
      stage = realpathSync(mkdtempSync(join(tmpdir(), "aab-downstream-")));
      chmodSync(stage, 0o700);
      if (isInside(realpathSync(root), stage)) throw new Error("The stage must be outside the candidate checkout; set TMPDIR elsewhere");
      Object.assign(paths, { upstream: join(stage, "upstream"), candidate: join(stage, "candidate"), provider: join(stage, "provider"),
        assembly: join(stage, "assembly"), registry: join(stage, "registry"), cargoHome: join(stage, "cargo-home"),
        home: join(stage, "home"), run: join(stage, "run") });
      report.stage = { path: stage, deleted: false };
      mkdirSync(paths.home, { mode: 0o700 });
      gitEnv = isolatedGitEnvironment(clean, { home: paths.home, protocols: source === "canonical" ? "file:https" : "file" });
      report.gitIsolation = { home: "stage-owned and empty", systemConfig: "disabled", globalConfig: devNull, allowedProtocols: gitEnv.GIT_ALLOW_PROTOCOL };
      await git("clone-upstream", stage, ["clone", "--bare", "--no-local", "--no-hardlinks", "--quiet", root, paths.upstream]);
      if (existsSync(join(paths.upstream, "objects", "info", "alternates"))) {
        throw new Error("The staged upstream clone must not borrow objects through alternates");
      }
      if (gitText(paths.upstream, ["rev-parse", "--verify", `${commit}^{commit}`]) !== commit) {
        throw new Error("The staged upstream clone does not contain the candidate commit");
      }
      await git("detach-upstream", paths.upstream, ["update-ref", "--no-deref", "HEAD", commit]);
      const refs = gitText(paths.upstream, ["for-each-ref", "--format=%(refname)"]).split("\n").filter(Boolean);
      if (refs.length) {
        await git("prune-upstream-refs", paths.upstream, ["update-ref", "--stdin"], { input: refs.map((ref) => `delete ${ref}\n`).join("") });
      }
      await git("advertise-candidate", paths.upstream, ["update-ref", "refs/heads/candidate", commit]);
      await git("remove-origin", paths.upstream, ["remote", "remove", "origin"]);
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
    for (const name of [SDK_PACKAGE, PROVIDER_PACKAGE, CLI_PACKAGE, "agent-access-broker-host", "agent-access-cloudbees-ci"]) {
      if (!upstreamNames.has(name)) throw new Error(`The candidate workspace has no ${name} package`);
    }
    const seed = thirdPartyLockSeed(candidateLockText);

    await step("registry-source", async (record) => {
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
        const unpacked = await supervisor.run("tar", ["-xzf", file, "-C", extraction], { env: clean, stderr: "pipe" });
        if (unpacked.error || unpacked.code !== 0) {
          throw new Error(`Extracting ${file} failed: ${unpacked.error?.message ?? unpacked.stderr.toString("utf8").trim()}`);
        }
        const extracted = readdirSync(extraction);
        if (extracted.length !== 1 || extracted[0] !== directory) throw new Error(`${file} must contain only ${directory}/`);
        renameSync(join(extraction, directory), join(paths.registry, directory));
        rmSync(extraction, { recursive: true });
        writeFileSync(join(paths.registry, directory, ".cargo-checksum.json"), JSON.stringify({ files: {}, package: entry.checksum }));
      }
      mkdirSync(paths.cargoHome, { mode: 0o700 });
      const config = stagedCargoConfig(paths.registry);
      writeFileSync(join(paths.cargoHome, "config.toml"), config, { mode: 0o600 });
      writeFileSync(join(evidence, "cargo-home-config.toml"), config);
      record.detail = { crates: archives.length, cacheDirectories };
      report.registry = { replacement: "directory source built from the shared download cache", crates: archives.length, cacheDirectories };
      report.cargoConfiguration = { private: join(paths.cargoHome, "config.toml"), sha256: sha256(config), checkedDirectories: [] };
    });

    const rustdoc = realpathSync(join(dirname(toolchain.rustcPath), executable("rustdoc")));
    const rustfmt = realpathSync(join(dirname(toolchain.rustcPath), executable("rustfmt")));
    const cargoEnv = { ...gitEnv, CARGO_HOME: paths.cargoHome, RUSTC: toolchain.rustcPath, RUSTDOC: rustdoc, CARGO_TERM_COLOR: "never" };
    const cargo = (label, cwd, args, options = {}) => execute(label, toolchain.cargoPath, args, { cwd, env: cargoEnv, ...options });
    const targetDirectory = (directory) => ["--target-dir", join(directory, "target")];
    const extract = async (label, path, destination, strip) => {
      const archive = await git(`${label}-archive`, paths.upstream, ["archive", "--format=tar", commit, ...(path ? ["--", path] : [])], { capture: true });
      await execute(`${label}-extract`, "tar", ["-x", "-C", destination, ...(strip ? [`--strip-components=${strip}`] : [])],
        { cwd: destination, env: clean, input: archive });
    };
    const commitRepository = async (label, directory, message) => {
      const identity = { GIT_AUTHOR_NAME: "Downstream Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid",
        GIT_COMMITTER_NAME: "Downstream Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid",
        GIT_AUTHOR_DATE: report.upstream.committedAt, GIT_COMMITTER_DATE: report.upstream.committedAt };
      await git(`${label}-init`, directory, ["init", "--quiet", "--initial-branch=main"]);
      await git(`${label}-add`, directory, ["add", "--all"]);
      await execute(`${label}-commit`, "git", ["commit", "--quiet", "--no-verify", "-m", message], { cwd: directory, env: { ...gitEnv, ...identity } });
      return gitText(directory, ["rev-parse", "HEAD"]);
    };
    const assertToolchain = (directory) => {
      const channel = toolchainChannel(readFileSync(join(directory, "rust-toolchain.toml"), "utf8"));
      if (channel !== toolchain.pinned) throw new Error(`${directory} pins ${channel}; the candidate pins ${toolchain.pinned}`);
    };
    // Runs after a repository's files are in place and before Cargo first
    // runs there, so committed or ancestor configuration cannot apply.
    const assertCargoConfiguration = (directory) => {
      const foreign = foreignCargoConfigs(directory, paths.cargoHome);
      report.cargoConfiguration.checkedDirectories.push(directory);
      if (foreign.length) {
        throw new Error(`Cargo configuration outside the stage's private Cargo home applies to ${directory}: `
          + `${foreign.map((config) => config.path).join(", ")}. Remove it, or set TMPDIR to a directory without Cargo configuration in its ancestors.`);
      }
    };
    const upstreamSource = { canonical: CANONICAL_UPSTREAM_URL, url: upstreamSourceUrl, rev: commit, packages: upstreamNames };
    const mapping = { schemaVersion: 1, mode: source, candidate: { commit, committedAt: report.upstream.committedAt },
      sources: [], manifests: [] };
    let cli;
    let providerCommit;

    await step("candidate-cli", async (record) => {
      mkdirSync(paths.candidate, { mode: 0o700 });
      await extract("candidate", null, paths.candidate, 0);
      assertToolchain(paths.candidate);
      assertCargoConfiguration(paths.candidate);
      const args = ["build", "--locked", "--offline", "-p", CLI_PACKAGE, ...targetDirectory(paths.candidate)];
      await cargo("candidate-cli-build", paths.candidate, args);
      cli = join(paths.candidate, "target", "debug", executable(CLI_PACKAGE));
      accessSync(cli, constants.X_OK);
      const bytes = readFileSync(cli);
      report.cli = { builtFrom: commit, source: "git archive of the candidate commit from the staged clone, built in the stage",
        command: ["cargo", ...args], sha256: sha256(bytes), bytes: bytes.length };
      record.detail = { sha256: report.cli.sha256 };
    });

    await step("stage-provider", async (record) => {
      mkdirSync(paths.provider, { mode: 0o700 });
      await extract("provider-template", `${FIXTURE_DIRECTORY}/provider-repo`, paths.provider, 3);
      await extract("provider-crate", PROVIDER_CRATE_DIRECTORY, paths.provider, 0);
      assertToolchain(paths.provider);
      assertCargoConfiguration(paths.provider);
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
      const rootManifest = rewriteStagedManifest(`${template.trimEnd()}\n${inherited.join("\n")}\n`, [upstreamSource]);
      const crate = rewriteStagedManifest(normalized.text, [upstreamSource]);
      writeFileSync(rootPath, rootManifest.text);
      writeFileSync(crateManifestPath, crate.text);
      writeFileSync(join(paths.provider, "Cargo.lock"), seed);
      mapping.manifests.push({ repository: "provider", path: "Cargo.toml", rewrites: rootManifest.rewrites, inheritedFromCandidate: normalized.inherited },
        { repository: "provider", path: `${PROVIDER_CRATE_DIRECTORY}/Cargo.toml`, rewrites: crate.rewrites,
          normalized: `${SDK_PACKAGE} path dependency replaced by the provider workspace pin` });
      await cargo("provider-setup-fetch", paths.provider, ["fetch"]);
      providerCommit = await commitRepository("provider", paths.provider,
        `Provider repository staged from ${commit}\n\nContains ${PROVIDER_CRATE_DIRECTORY} and ${FIXTURE_DIRECTORY}/provider-repo.`);
      record.detail = { commit: providerCommit };
    });

    const providerSourceUrl = pathToFileURL(paths.provider).href;
    let assemblyCommit;
    await step("stage-assembly", async (record) => {
      mkdirSync(paths.assembly, { mode: 0o700 });
      await extract("assembly-template", `${FIXTURE_DIRECTORY}/assembly-repo`, paths.assembly, 3);
      assertToolchain(paths.assembly);
      assertCargoConfiguration(paths.assembly);
      const manifestPath = join(paths.assembly, "Cargo.toml");
      const sources = [
        { canonical: CANONICAL_PROVIDER_URL, url: providerSourceUrl, rev: providerCommit, packages: new Set([PROVIDER_PACKAGE]) },
        upstreamSource,
      ];
      const manifest = rewriteStagedManifest(readFileSync(manifestPath, "utf8"), sources);
      writeFileSync(manifestPath, manifest.text);
      writeFileSync(join(paths.assembly, "Cargo.lock"), seed);
      mapping.manifests.push({ repository: "assembly", path: "Cargo.toml", rewrites: manifest.rewrites });
      await cargo("assembly-setup-fetch", paths.assembly, ["fetch"]);
      assemblyCommit = await commitRepository("assembly", paths.assembly, `Downstream assembly staged from ${commit}`);
      record.detail = { commit: assemblyCommit };
    });

    mapping.sources.push(
      { role: "upstream", canonical: { git: CANONICAL_UPSTREAM_URL, rev: SENTINEL_REV }, staged: { git: upstreamSourceUrl, rev: commit },
        lockSource: gitSourceId(upstreamSourceUrl, commit), advertisedRefs: report.upstream.advertisedRefs },
      { role: "provider", canonical: { git: CANONICAL_PROVIDER_URL, rev: SENTINEL_REV }, staged: { git: providerSourceUrl, rev: providerCommit },
        lockSource: gitSourceId(providerSourceUrl, providerCommit),
        contents: [`${PROVIDER_CRATE_DIRECTORY} at ${commit}`, `${FIXTURE_DIRECTORY}/provider-repo at ${commit}`] },
      { role: "assembly", repository: "local only", commit: assemblyCommit, contents: [`${FIXTURE_DIRECTORY}/assembly-repo at ${commit}`] },
      { role: "cli", builtFrom: commit, sha256: report.cli.sha256 },
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

    await step("provider-tests", async () => {
      await cargo("provider-test", paths.provider, ["test", "--locked", "--offline", ...targetDirectory(paths.provider)]);
    });

    await step("provider-boundaries", async (record) => {
      const metadata = JSON.parse((await cargo("provider-metadata", paths.provider,
        ["metadata", "--locked", "--offline", "--format-version", "1"], { capture: true })).toString("utf8"));
      const tree = (await cargo("provider-tree", paths.provider,
        ["tree", "--locked", "--offline", "-e", "normal,build,dev,features", "--target", "all"], { capture: true })).toString("utf8");
      writeFileSync(join(evidence, "cargo-tree-provider.txt"), tree);
      const violations = providerBoundaryViolations(metadata);
      record.detail = { packages: metadata.packages.length };
      if (violations.length) throw new Error(`The provider repository reaches forbidden upstream crates:\n${violations.join("\n")}`);
    });

    const binary = join(paths.assembly, "target", "debug", executable(ASSEMBLY_PACKAGE));
    // The build process stamps the assembly's own revision and qualification
    // label, as a downstream release pipeline does for a verified clean
    // checkout; its build script reads the module revisions from Cargo.lock.
    const assemblyEnv = { ...cargoEnv, DOWNSTREAM_BROKER_REVISION: assemblyCommit, DOWNSTREAM_BROKER_QUALIFICATION: FIXTURE_QUALIFICATION };
    await step("assembly-build", async (record) => {
      await execute("assembly-format", rustfmt, ["--check", "--edition", ASSEMBLY_EDITION, "build.rs", "src/lib.rs", "src/main.rs"],
        { cwd: paths.assembly, env: cargoEnv });
      await execute("assembly-test", toolchain.cargoPath, ["test", "--locked", "--offline", ...targetDirectory(paths.assembly)],
        { cwd: paths.assembly, env: assemblyEnv });
      // Built last, so the executable is the release graph's, without the
      // development features its tests unify.
      await execute("assembly-build", toolchain.cargoPath, ["build", "--locked", "--offline", ...targetDirectory(paths.assembly)],
        { cwd: paths.assembly, env: assemblyEnv });
      accessSync(binary, constants.X_OK);
      record.detail = { revision: assemblyCommit, qualification: FIXTURE_QUALIFICATION };
    });

    await step("assembly-features", async (record) => {
      const tree = (await cargo("assembly-tree", paths.assembly, assemblyFeatureTreeArgs(toolchain.host),
        { capture: true })).toString("utf8");
      writeFileSync(join(evidence, "cargo-tree-assembly-features.txt"), tree);
      const violations = assemblyFeatureViolations(tree);
      record.detail = { target: toolchain.host, packages: parseCargoTree(tree).length };
      if (violations.length) throw new Error(`The assembly release graph enables test support:\n${violations.join("\n")}`);
    });

    await step("process-acceptance", async (record) => {
      const assemblyLock = parseLockfile(readFileSync(join(paths.assembly, "Cargo.lock"), "utf8"));
      const locked = (name, source) => {
        const entries = assemblyLock.packages.filter((entry) => entry.name === name && entry.source === source);
        if (entries.length !== 1) throw new Error(`The assembly lock must hold exactly one ${name} from ${source}`);
        return entries[0].version;
      };
      const upstreamLock = gitSourceId(upstreamSourceUrl, commit);
      const providerLock = gitSourceId(providerSourceUrl, providerCommit);
      const expectedStatus = expectedAssemblyStatus({
        assembly: { name: ASSEMBLY_PACKAGE, version: locked(ASSEMBLY_PACKAGE, null), qualification: FIXTURE_QUALIFICATION, revision: assemblyCommit },
        host: { version: locked(HOST_PACKAGE, upstreamLock), revision: commit },
        sdk: { version: locked(SDK_PACKAGE, upstreamLock), revision: commit },
        modules: [
          { crate: CLOUDBEES_PACKAGE, version: locked(CLOUDBEES_PACKAGE, upstreamLock), roles: [{ role: "native", id: "cloudbees_ci" }], revision: commit },
          { crate: PROVIDER_PACKAGE, version: locked(PROVIDER_PACKAGE, providerLock), roles: [{ role: "native", id: "conformance" }], revision: providerCommit },
        ],
      });
      writeFileSync(join(evidence, "expected-status.json"), `${JSON.stringify(expectedStatus, null, 2)}\n`);
      report.acceptance = await runProcessAcceptance({ supervisor, binary, cli, run: paths.run, evidence,
        env: { ...clean, HOME: paths.home }, platform, expectedStatus });
      record.detail = { checks: report.acceptance.checks.length, shutdown: report.acceptance.shutdown };
    });

    supervisor.assertRunning();
    assertQualificationSource(root, commit, clean);
    report.status = "passed";
  } catch (error) {
    const interrupted = supervisor.interruption;
    report.status = interrupted ? "interrupted" : "failed";
    report.error = interrupted && !(error instanceof InterruptedError) ? `Interrupted by ${interrupted}: ${error.message}` : error.message;
    throw interrupted ? new InterruptedError(interrupted) : error;
  } finally {
    try {
      try {
        await supervisor.stopAll();
      } catch (error) {
        report.cleanupError = error.message;
      }
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
      report.strayProcessGroups = supervisor.strays;
      if (supervisor.interruption && report.status === "passed") {
        report.status = "interrupted";
        report.error = `Interrupted by ${supervisor.interruption} during cleanup`;
      } else if (report.cleanupError && report.status === "passed") {
        report.status = "failed";
        report.error = `Child process cleanup failed: ${report.cleanupError}`;
      }
      report.finishedAt = stamp();
      save();
      removeHandlers();
    }
  }
  if (report.status === "interrupted") throw new InterruptedError(supervisor.interruption);
  if (report.status === "failed") throw new Error(report.error);
  console.log(`Downstream consumer passed at ${commit}: ${join(evidence, "status.json")}`);
  return report;
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH)) {
  try {
    await runDownstreamConsumer(parseConsumerArguments(process.argv.slice(2)));
  } catch (error) {
    console.error(error.message);
    process.exitCode = error instanceof InterruptedError ? 128 + (osConstants.signals[error.signal] ?? 0) : 1;
  }
}
