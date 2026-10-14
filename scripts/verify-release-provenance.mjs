#!/usr/bin/env node

import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { accessSync, chmodSync, constants, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { CARGO_TARGET_DIRECTORY, parseRustcHost, repositoryBinaries } from "./portal-binaries.mjs";
import { assertNoGitOverrides } from "./release-environment.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const ROOT = join(dirname(SCRIPT_PATH), "..");
const FULL_OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const START_TIMEOUT_MS = 15_000;
const STOP_TIMEOUT_MS = 5_000;
const LOG_TAIL_BYTES = 32 * 1024;
const TOOLCHAIN_OVERRIDE_VARIABLES = new Set([
  "CARGO", "RUSTUP_TOOLCHAIN", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
  "RUSTC_BOOTSTRAP", "RUSTC_STAGE", "RUSTDOC", "RUSTFLAGS", "RUSTDOCFLAGS", "RUST_TARGET_PATH",
  "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
  "CARGO_BUILD_RUSTDOC", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTDOCFLAGS",
  "CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS", "CARGO_INCREMENTAL", "CARGO_BUILD_INCREMENTAL",
]);

export function assertNoToolchainOverrides(env) {
  const overrides = Object.keys(env).filter((name) => env[name] !== undefined && env[name] !== ""
    && (TOOLCHAIN_OVERRIDE_VARIABLES.has(name) || name.startsWith("CARGO_PROFILE_")
      || /^CARGO_TARGET_.+_(?:RUSTFLAGS|RUSTDOCFLAGS|LINKER|RUNNER)$/.test(name)
      || /^(?:(?:HOST|TARGET)_)?(?:CC|CXX|AR|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS)(?:_|$)/.test(name)));
  if (overrides.length) throw new Error(`Unset release compiler/toolchain/flag/profile overrides: ${overrides.sort().join(", ")}`);
}

export function validateToolchainVersions(pinned, rustcVerbose, cargoVersion) {
  if (!/^\d+\.\d+\.\d+$/.test(pinned)
      || /^rustc (\S+)/m.exec(rustcVerbose)?.[1] !== pinned
      || /^release: (\S+)$/m.exec(rustcVerbose)?.[1] !== pinned
      || /^cargo (\S+)/.exec(cargoVersion)?.[1] !== pinned) {
    throw new Error(`Release toolchain must match rust-toolchain.toml (${pinned}); found ${rustcVerbose.split("\n")[0]} and ${cargoVersion}`);
  }
  return parseRustcHost(rustcVerbose);
}

export function cargoConfigInventory(root, env = process.env) {
  const directories = [];
  for (let directory = resolve(root);; directory = dirname(directory)) {
    directories.push(join(directory, ".cargo"));
    if (directory === dirname(directory)) break;
  }
  const home = (process.platform === "win32" ? env.USERPROFILE : env.HOME) || homedir();
  directories.push(resolve(root, env.CARGO_HOME || join(home, ".cargo")));
  return [...new Set(directories)].flatMap((directory) => {
    const legacy = join(directory, "config");
    return [legacy, join(directory, "config.toml")].filter(existsSync).map((file) => ({
      path: file,
      selected: file === legacy || !existsSync(legacy),
      sha256: createHash("sha256").update(readFileSync(file)).digest("hex"),
    }));
  });
}

export function inspectLocalToolchain(root = ROOT, { env = process.env, run = execFileSync, platform = process.platform } = {}) {
  assertNoToolchainOverrides(env);
  const toolchainFile = readFileSync(join(root, "rust-toolchain.toml"), "utf8");
  const section = /^\[toolchain\]\s*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/m.exec(toolchainFile)?.[1];
  const pinned = /^\s*channel\s*=\s*"(\d+\.\d+\.\d+)"\s*(?:#.*)?$/m.exec(section ?? "")?.[1];
  if (!pinned) throw new Error("rust-toolchain.toml must pin an exact stable toolchain version");
  const output = (command, args) => run(command, args, {
    cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  }).toString().trim();
  const rustcVerbose = output("rustc", ["-vV"]);
  const cargoVersion = output("cargo", ["-V"]);
  const host = validateToolchainVersions(pinned, rustcVerbose, cargoVersion);
  // Resolve through the checked compiler's sysroot, not a rustup shim whose
  // behavior could later change with cwd or toolchain configuration.
  const sysroot = output("rustc", ["--print", "sysroot"]);
  if (!isAbsolute(sysroot)) throw new Error("rustc --print sysroot must return an absolute path");
  const suffix = platform === "win32" ? ".exe" : "";
  const rustcPath = realpathSync(join(sysroot, "bin", `rustc${suffix}`));
  const cargoPath = realpathSync(join(sysroot, "bin", `cargo${suffix}`));
  accessSync(rustcPath, constants.X_OK);
  accessSync(cargoPath, constants.X_OK);
  if (output(rustcPath, ["-vV"]) !== rustcVerbose || output(cargoPath, ["-V"]) !== cargoVersion) {
    throw new Error("Validated sysroot compiler/Cargo do not match the tools selected on PATH");
  }
  return { pinned, host, rustcPath, cargoPath, rustcVerbose, cargoVersion,
    cargoConfigs: cargoConfigInventory(root, env) };
}

export function parseProvenanceArguments(args) {
  const references = args.filter((arg) => !arg.startsWith("--"));
  const options = args.filter((arg) => arg.startsWith("--"));
  if (references.length !== 1 || !references[0] || options.length > 1 || options.some((arg) => arg !== "--build-service")) {
    throw new Error("Usage: node scripts/verify-release-provenance.mjs <full-commit|exact-tag> [--build-service]");
  }
  return { expectedRef: references[0], buildService: options.includes("--build-service") };
}

export function provenanceBuildPlan(commit, { buildService = false, env = process.env, root = ROOT, platform = process.platform, toolchain } = {}) {
  if (!FULL_OBJECT_ID.test(commit)) throw new Error("Release provenance requires a full commit object ID");
  if (buildService && !env.BUILD_SERVICE_ENDPOINT?.trim()) {
    throw new Error("BUILD_SERVICE_ENDPOINT is required with --build-service");
  }
  assertNoToolchainOverrides(env);
  if (!toolchain || !isAbsolute(toolchain.rustcPath ?? "") || !isAbsolute(toolchain.cargoPath ?? "")) {
    throw new Error("Release build planning requires a validated local compiler and Cargo");
  }
  const host = validateToolchainVersions(toolchain.pinned, toolchain.rustcVerbose, toolchain.cargoVersion);
  const stamps = {
    AGENT_ACCESS_BUILD_COMMIT: commit,
    AGENT_ACCESS_BUILD_PROVENANCE: "release",
    AGENT_ACCESS_REQUIRE_BUILD_PROVENANCE: "1",
  };
  const buildEnv = { ...env, ...stamps, BUILD_SERVICE_ENABLED: String(buildService) };
  delete buildEnv.CARGO_TARGET_DIR;
  delete buildEnv.CARGO_BUILD_TARGET_DIR;
  delete buildEnv.CARGO_BUILD_TARGET;
  const compilerArgs = buildService ? [] : [
    "--config", `build.rustc=${JSON.stringify(toolchain.rustcPath)}`,
    "--config", 'build.rustc-wrapper=""',
    "--config", 'build.rustc-workspace-wrapper=""',
  ];
  if (!buildService) Object.assign(buildEnv, {
    CARGO: toolchain.cargoPath,
    RUSTC: toolchain.rustcPath,
    CARGO_BUILD_RUSTC: toolchain.rustcPath,
    RUSTC_WRAPPER: "", RUSTC_WORKSPACE_WRAPPER: "",
    CARGO_BUILD_RUSTC_WRAPPER: "", CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER: "",
    // Encoded flags take precedence over both target and build config flags.
    RUSTFLAGS: "", CARGO_ENCODED_RUSTFLAGS: "", CARGO_BUILD_RUSTFLAGS: "",
  });
  const cargoArgs = ["build", "--release", "--locked", "--target-dir", CARGO_TARGET_DIRECTORY,
    "--target", host, "-p", "agent-access-broker", "-p", "agent-access"];
  return {
    command: buildService ? "build-cli" : toolchain.cargoPath,
    args: buildService ? ["build", "--endpoint", env.BUILD_SERVICE_ENDPOINT,
      ...Object.entries(stamps).flatMap(([name, value]) => ["--env", `${name}=${value}`]),
      "cargo", "--", ...cargoArgs] : [...compilerArgs, ...cargoArgs],
    cwd: root,
    env: buildEnv,
    toolchain,
    ...repositoryBinaries(root, "release", host, platform),
  };
}

export class StatusMetadataMismatch extends Error {
  constructor(message) {
    super(message);
    this.name = "StatusMetadataMismatch";
  }
}

const RELEASE_ASSEMBLY = "agent-access-broker";

// A release build records its one commit, backed by this verifier's clean
// checkout, for the assembly, the host, the SDK and every compiled module.
export function assertReleaseStatus(status, expected) {
  const evidence = (source) => source?.revision === expected.commit && source?.provenance === "evidence";
  const packages = [status?.host, status?.sdk, ...(Array.isArray(status?.modules) ? status.modules : [])];
  if (
    status?.assembly?.name !== RELEASE_ASSEMBLY ||
    status.assembly.version !== expected.version ||
    !evidence(status.assembly.source) ||
    status.host?.crate !== "agent-access-broker-host" ||
    status.sdk?.crate !== "agent-access-provider" ||
    !Array.isArray(status.modules) || status.modules.length === 0 ||
    !packages.every((entry) => entry?.version === expected.version && evidence(entry.source))
  ) {
    throw new StatusMetadataMismatch(
      `status mismatch: expected ${RELEASE_ASSEMBLY} version=${expected.version} with evidence-backed commit=${expected.commit} for the assembly, host, SDK and every module; received ${JSON.stringify(status)}`,
    );
  }
}

const RELEASE_PACKAGES = ["agent-access-broker", "agent-access"];
const FORBIDDEN_RELEASE_FEATURE = "test-support";

// Resolves features for the normal and build units of a release build of both
// packages: without dev edges Cargo resolves no dev units. `{f}` is each unit's
// resolved feature set, which includes features enabled by a root's defaults
// that a feature-edge traversal does not display.
export function releaseFeatureTreeArgs(host) {
  return ["tree", "--locked", "--target", host,
    ...RELEASE_PACKAGES.flatMap((name) => ["-p", name]),
    "-e", "normal,build", "--prefix", "none", "--format", "{p}\t{f}"];
}

// Parses `releaseFeatureTreeArgs` output, one `<package>\t<features>` line per
// unit, into packages with the union of their resolved features. A package is
// its `{p}` identity: name, version and, outside crates.io, the source Cargo
// displays (an absolute directory for a path package, `url#<short commit>` for
// Git), so two origins of one name and version stay distinct. Headings, blank
// lines and `(*)` repeat markers name no unit.
export function parseCargoTree(output) {
  const packages = new Map();
  for (const line of output.split(/\r?\n/)) {
    const [unit, features = ""] = line.split("\t");
    const pkg = /^(\S+) v(\S+)(?: \(proc-macro\))?(?: \((.*)\))?$/.exec(unit.trim());
    if (!pkg) continue;
    const identity = unit.trim();
    const entry = packages.get(identity)
      ?? { name: pkg[1], version: pkg[2], source: pkg[3] ?? null, features: new Set() };
    for (const feature of features.replace(/ \(\*\)$/, "").split(",")) {
      if (feature.trim()) entry.features.add(feature.trim());
    }
    packages.set(identity, entry);
  }
  return [...packages.values()].map((entry) => ({ ...entry, features: [...entry.features].sort() }));
}

// Workspace members whose `[package.metadata.agent-access] role` is `reference`.
export function referenceCrates(metadata) {
  const members = new Set(metadata.workspace_members ?? []);
  return (metadata.packages ?? [])
    .filter((pkg) => members.has(pkg.id) && pkg.metadata?.["agent-access"]?.role === "reference")
    .map((pkg) => pkg.name)
    .sort();
}

// Release executables must not enable a test-support feature or link a
// reference crate through normal or build edges.
export function assertReleaseFeatureGraph(output, references) {
  const packages = parseCargoTree(output);
  const missing = RELEASE_PACKAGES.filter((name) => !packages.some((pkg) => pkg.name === name));
  if (missing.length) {
    throw new Error(`cargo tree output omits release package ${missing.join(", ")}`);
  }
  const problems = [
    ...packages.filter((pkg) => pkg.features.includes(FORBIDDEN_RELEASE_FEATURE))
      .map((pkg) => `test feature ${pkg.name}/${FORBIDDEN_RELEASE_FEATURE}`),
    ...packages.filter((pkg) => references.includes(pkg.name)).map((pkg) => `reference crate ${pkg.name}`),
  ];
  if (problems.length) {
    throw new Error(`Release dependency graph enables test-only code: ${[...new Set(problems)].sort().join(", ")}`);
  }
}

// The source origins of each `name version` among the units a release build
// selects, from the same no-dev resolution as the feature check. Optional
// dependencies that only development features activate are not selected, and
// origins are never merged.
export function releasePackageOrigins(output) {
  const origins = new Map();
  for (const pkg of parseCargoTree(output)) {
    const key = `${pkg.name} ${pkg.version}`;
    origins.set(key, [...(origins.get(key) ?? []), { source: pkg.source }]);
  }
  return origins;
}

// The upstream release stamps the qualified commit on the host, the SDK and
// every module, so each must resolve to exactly one origin: a path package
// whose manifest Git tracks inside the qualified checkout. A same-version
// package from another source, or two origins sharing a key, is rejected.
export function assertStampedSources(status, origins, { root, tracked, realpath = realpathSync }) {
  const checkout = realpath(root);
  const problems = [];
  for (const entry of [status.host, status.sdk, ...status.modules]) {
    const key = `${entry.crate} ${entry.version}`;
    const resolved = origins.get(key) ?? [];
    if (resolved.length !== 1) {
      problems.push(resolved.length
        ? `${key} resolves to ${resolved.length} source origins (${resolved.map((origin) => origin.source ?? "crates.io").sort().join(", ")})`
        : `${key} is not in the resolved release graph`);
      continue;
    }
    const [{ source }] = resolved;
    const manifest = source !== null && isAbsolute(source)
      ? relative(checkout, realpath(join(source, "Cargo.toml"))).split(sep).join("/")
      : null;
    if (manifest === null || manifest.startsWith("../") || isAbsolute(manifest) || !tracked.has(manifest)) {
      problems.push(`${key} resolves to ${source ?? "crates.io"}, not a committed path package in the qualified checkout`);
    }
  }
  if (problems.length) {
    throw new StatusMetadataMismatch(`status provenance does not match resolved sources: ${problems.join("; ")}`);
  }
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

// Resolved dependency trees and metadata can exceed the default 1 MiB.
const CAPTURE_MAX_BYTES = 256 * 1024 * 1024;

function capture(command, args, env = process.env) {
  try {
    return execFileSync(command, args, {
      cwd: ROOT,
      env,
      encoding: "utf8",
      maxBuffer: CAPTURE_MAX_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    const stderr = error.stderr?.toString().trim();
    const detail = stderr || (error.code ? String(error.code) : "");
    fail(`${command} ${args.join(" ")} failed${detail ? `: ${detail}` : ""}`);
  }
}

function resolveExpectedCommit(value) {
  if (FULL_OBJECT_ID.test(value)) {
    const resolved = capture("git", ["rev-parse", "--verify", `${value}^{commit}`]);
    if (resolved !== value) {
      fail(`full commit does not resolve canonically: expected ${value}, resolved ${resolved}`);
    }
    return resolved;
  }
  capture("git", ["show-ref", "--verify", `refs/tags/${value}`]);
  return capture("git", ["rev-parse", "--verify", `refs/tags/${value}^{commit}`]);
}

export function assertCleanAt(commit, stage, { root = ROOT, env = process.env } = {}) {
  assertNoGitOverrides(env);
  const git = (args) => execFileSync("git", args, {
    cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  const gitRoot = git(["rev-parse", "--show-toplevel"]);
  if (realpathSync(gitRoot) !== realpathSync(root)) {
    throw new Error(`${stage}: Git checkout root differs from the verifier repository`);
  }
  const status = git(["status", "--porcelain"]);
  if (status) {
    throw new Error(`${stage}: checkout is not clean:\n${status}`);
  }
  const head = git(["rev-parse", "HEAD"]);
  if (head !== commit) {
    throw new Error(`${stage}: HEAD changed: expected ${commit}, found ${head}`);
  }
}

// The validated local Cargo and compiler, which resolve the host target's
// configuration for metadata and tree queries in either build mode.
function localCargoEnv(toolchain, env) {
  return { ...env, CARGO: toolchain.cargoPath, RUSTC: toolchain.rustcPath, CARGO_BUILD_RUSTC: toolchain.rustcPath };
}

function workspaceMetadata(toolchain, env) {
  const metadata = JSON.parse(capture(toolchain.cargoPath,
    ["metadata", "--locked", "--no-deps", "--format-version", "1"], localCargoEnv(toolchain, env)));
  const broker = metadata.packages.find((entry) => entry.name === "agent-access-broker");
  if (!broker) {
    fail("agent-access-broker package was not found in cargo metadata");
  }
  return { version: broker.version, references: referenceCrates(metadata) };
}

// Checks the release units' features and returns their source origins.
function verifyReleaseFeatures(toolchain, env, references) {
  const output = capture(toolchain.cargoPath, releaseFeatureTreeArgs(toolchain.host), localCargoEnv(toolchain, env));
  assertReleaseFeatureGraph(output, references);
  return releasePackageOrigins(output);
}

function trackedFiles() {
  return new Set(capture("git", ["ls-files", "-z"]).split("\0").filter(Boolean));
}

function buildBinaries(plan) {
  const result = spawn(plan.command, plan.args, {
    cwd: plan.cwd,
    env: plan.env,
    stdio: "inherit",
  });
  return new Promise((resolve, reject) => {
    result.once("error", reject);
    result.once("exit", (code, signal) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${plan.command} failed with code ${code ?? "null"}, signal ${signal ?? "none"}`));
      }
    });
  });
}

// The Broker's default log filter (`DEFAULT_LOG_FILTER` in the host's
// lifecycle), set for each Broker a gate starts. An inherited RUST_LOG such
// as `warn` would otherwise hide the INFO `broker_listening` event that names
// the Broker's bound address.
export const BROKER_LOG_FILTER =
  "agent_access_broker=info,agent_access_broker_host=info,agent_access_core=info,agent_access_provider=info,axum=warn,tower=warn";

// The environment of the Broker whose status provenance verification reads.
export function verificationBrokerEnvironment(env, token) {
  return { ...env, RUST_LOG: BROKER_LOG_FILTER, AGENT_ACCESS_PROVENANCE_VERIFY_TOKEN: token };
}

// The address of the public `broker_listening` event in `log`, the Broker's
// JSON lines, or null before it is logged. A Broker started with
// `--listen <host>:0` reports the port it bound there, so no port has to be
// chosen in advance and left for another process to take.
export function publicListeningAddress(log, host = "127.0.0.1") {
  for (const line of log.split("\n")) {
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      continue;
    }
    if (event?.event !== "broker_listening" || event.listener !== "public") continue;
    const match = typeof event.address === "string" ? /^(.+):(\d+)$/.exec(event.address) : null;
    const port = match ? Number(match[2]) : 0;
    if (!match || match[1] !== host || port < 1 || port > 65_535) {
      throw new Error(`broker_listening must report the bound ${host} address; found ${JSON.stringify(event.address)}`);
    }
    return `${host}:${port}`;
  }
  return null;
}

function appendTail(current, chunk) {
  const combined = Buffer.concat([current, Buffer.from(chunk)]);
  return combined.length <= LOG_TAIL_BYTES
    ? combined
    : combined.subarray(combined.length - LOG_TAIL_BYTES);
}

async function stopChild(child) {
  if (!child.pid) return;
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const stopped = await Promise.race([
    new Promise((resolve) => child.once("exit", () => resolve(true))),
    new Promise((resolve) => setTimeout(() => resolve(false), STOP_TIMEOUT_MS)),
  ]);
  if (!stopped && child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await new Promise((resolve) => child.once("exit", resolve));
  }
}

async function verifyRunningBinary(binary, commit, version, sources) {
  const temporary = mkdtempSync(join(tmpdir(), "agent-access-provenance-"));
  chmodSync(temporary, 0o700);
  const configPath = join(temporary, "broker.toml");
  const token = `provenance-${randomUUID()}`;
  const config = `
[deployment]
environment = "development"

[identity]
mode = "required"
authority = "toml"

[[identity.sources]]
name = "verification"
type = "static_principals"
header = "Authorization"
scheme = "Bearer"

[[identity.sources.principals]]
principal = "provenance-verifier"
token_refs = ["env:AGENT_ACCESS_PROVENANCE_VERIFY_TOKEN"]

[policy]
authority = "toml"
default_decision = "deny"
`;
  writeFileSync(configPath, config, { mode: 0o600 });
  const child = spawn(
    binary,
    ["--config", configPath, "serve", "--listen", "127.0.0.1:0"],
    {
      cwd: ROOT,
      env: verificationBrokerEnvironment(process.env, token),
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdoutTail = Buffer.alloc(0);
  let stderrTail = Buffer.alloc(0);
  let spawnError = null;
  child.once("error", (error) => {
    spawnError = error;
  });
  child.stdout.on("data", (chunk) => {
    stdoutTail = appendTail(stdoutTail, chunk);
  });
  let address = null;
  let addressError = null;
  let addressLog = "";
  child.stderr.on("data", (chunk) => {
    stderrTail = appendTail(stderrTail, chunk);
    if (address === null && addressError === null) {
      addressLog += chunk.toString("utf8");
      try {
        address = publicListeningAddress(addressLog);
      } catch (error) {
        addressError = error;
      }
    }
  });

  try {
    const deadline = Date.now() + START_TIMEOUT_MS;
    let lastError = "broker did not answer";
    while (Date.now() < deadline) {
      if (spawnError) throw spawnError;
      if (child.exitCode !== null || child.signalCode !== null) {
        throw new Error(`broker exited before verification with code ${child.exitCode ?? "null"}`);
      }
      if (addressError) throw addressError;
      if (address === null) {
        lastError = "broker did not report its public listener";
        await new Promise((resolve) => setTimeout(resolve, 100));
        continue;
      }
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 1_000);
        const response = await fetch(`http://${address}/v1/broker/status`, {
          headers: {
            Authorization: `Bearer ${token}`,
            "X-Agent-Access-Request-Id": "release-provenance-verification",
          },
          signal: controller.signal,
        });
        clearTimeout(timeout);
        if (response.ok) {
          const status = await response.json();
          assertReleaseStatus(status, { commit, version });
          assertStampedSources(status, sources.origins, { root: ROOT, tracked: sources.tracked });
          return;
        }
        lastError = `status returned HTTP ${response.status}`;
      } catch (error) {
        if (error instanceof StatusMetadataMismatch) throw error;
        lastError = error.message;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(lastError);
  } catch (error) {
    const stdout = stdoutTail.toString("utf8").trim();
    const stderr = stderrTail.toString("utf8").trim();
    throw new Error(
      `${error.message}${stdout ? `\nBroker stdout tail:\n${stdout}` : ""}${stderr ? `\nBroker stderr tail:\n${stderr}` : ""}`,
    );
  } finally {
    await stopChild(child);
    rmSync(temporary, { recursive: true, force: true });
  }
}

async function main() {
  try {
    assertNoGitOverrides();
    const options = parseProvenanceArguments(process.argv.slice(2));
    const commit = resolveExpectedCommit(options.expectedRef);
    assertCleanAt(commit, "before build");
    const toolchain = inspectLocalToolchain();
    const plan = provenanceBuildPlan(commit, { ...options, toolchain });
    const { version, references } = workspaceMetadata(toolchain, plan.env);
    const tracked = trackedFiles();
    const origins = verifyReleaseFeatures(toolchain, plan.env, references);
    console.log(`Release feature check: no ${FORBIDDEN_RELEASE_FEATURE} feature or reference crate (${references.join(", ") || "none declared"}) in the normal/build graph of ${RELEASE_PACKAGES.join(" and ")}`);
    console.log(`Toolchain verification: ${JSON.stringify({
      ...toolchain,
      buildToolchain: options.buildService ? "Remote compiler and Cargo are unverified; local toolchain supplies metadata and native target only" : "Validated local compiler and Cargo; explicit compiler path, no wrappers or extra Rust flags",
      limits: "Not a hermetic build: normal Cargo config files are inventoried, but includes, profile/linker settings, build scripts, native tools and system libraries can affect output. Remote service configuration is not inventoried.",
    }, null, 2)}`);
    console.log(`Verifying Broker and CLI ${version} at ${commit} using ${plan.command}`);
    await buildBinaries(plan);
    assertCleanAt(commit, "after build");
    capture(plan.cliBinary, ["--help"]);
    await verifyRunningBinary(plan.brokerBinary, commit, version, { origins, tracked });
    assertCleanAt(commit, "after status verification");
    console.log(`Verified release provenance: version=${version} commit=${commit}`);
  } catch (error) {
    fail(error.message);
  }
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH)) {
  await main();
}
