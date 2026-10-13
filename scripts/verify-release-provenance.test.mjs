import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  BROKER_LOG_FILTER,
  StatusMetadataMismatch,
  assertReleaseFeatureGraph,
  assertReleaseStatus,
  assertStampedSources,
  assertCleanAt,
  assertNoToolchainOverrides,
  cargoConfigInventory,
  inspectLocalToolchain,
  parseCargoTree,
  parseProvenanceArguments,
  provenanceBuildPlan,
  publicListeningAddress,
  referenceCrates,
  releaseFeatureTreeArgs,
  releasePackageOrigins,
  validateToolchainVersions,
  verificationBrokerEnvironment,
} from "./verify-release-provenance.mjs";

const expected = {
  version: "0.1.0",
  commit: "0123456789abcdef0123456789abcdef01234567",
};
const toolchain = {
  pinned: "1.98.1",
  host: "x86_64-unknown-linux-gnu",
  rustcPath: path.resolve("toolchain/bin/rustc"),
  cargoPath: path.resolve("toolchain/bin/cargo"),
  rustcVerbose: "rustc 1.98.1 (48a229cea 2026-09-01)\nbinary: rustc\nhost: x86_64-unknown-linux-gnu\nrelease: 1.98.1",
  cargoVersion: "cargo 1.98.1 (797e8a9bc 2026-08-05)",
  cargoConfigs: [],
};

function temporary(t) {
  const root = mkdtempSync(path.join(tmpdir(), "release-provenance-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function releaseStatus() {
  const source = { revision: expected.commit, provenance: "evidence" };
  return {
    assembly: { name: "agent-access-broker", version: expected.version, qualification: "unqualified", source: { ...source } },
    host: { crate: "agent-access-broker-host", version: expected.version, source: { ...source } },
    sdk: { crate: "agent-access-provider", version: expected.version, source: { ...source } },
    modules: [
      { crate: "agent-access-fake", version: expected.version, roles: [{ role: "native", id: "fake" }], source: { ...source } },
      { crate: "agent-access-jira", version: expected.version, roles: [{ role: "native", id: "jira" }], source: { ...source } },
    ],
    inventoryFingerprint: `sha256:${"0".repeat(64)}`,
    catalogVersion: "agent-access.catalog.v2",
    sendSchemaVersion: "agent-access.send.v1",
  };
}

test("the verification Broker logs with the fixed filter whatever RUST_LOG it inherits", () => {
  const env = verificationBrokerEnvironment({ RUST_LOG: "warn", PATH: "/usr/bin" }, "verify-token");
  assert.equal(env.RUST_LOG, BROKER_LOG_FILTER);
  assert.equal(env.PATH, "/usr/bin");
  assert.equal(env.AGENT_ACCESS_PROVENANCE_VERIFY_TOKEN, "verify-token");
});

test("the gates' Broker log filter is the Broker default, which logs its startup events", () => {
  const lifecycle = readFileSync(
    fileURLToPath(new URL("../crates/agent-access-broker-host/src/lifecycle.rs", import.meta.url)),
    "utf8",
  );
  assert.equal(BROKER_LOG_FILTER, /DEFAULT_LOG_FILTER: &str = "([^"]+)"/.exec(lifecycle)?.[1]);
  assert.ok(BROKER_LOG_FILTER.split(",").includes("agent_access_broker_host=info"));
});

test("reads the bound public address from the broker_listening event", () => {
  const event = (fields) => JSON.stringify({ level: "INFO", event: "broker_listening", nodeId: "node-1", ...fields });
  const starting = JSON.stringify({ event: "broker_starting", publicListen: "127.0.0.1:0" });
  assert.equal(publicListeningAddress(""), null);
  assert.equal(publicListeningAddress(`${starting}\nnot json\n`), null);
  assert.equal(publicListeningAddress(`${event({ listener: "gateway", address: "127.0.0.1:41000" })}\n`), null);
  assert.equal(
    publicListeningAddress(`${starting}\nnot json\n${event({ listener: "public", address: "127.0.0.1:41001" })}\n`),
    "127.0.0.1:41001",
  );
  // A partial line is not yet an event.
  assert.equal(publicListeningAddress(`${starting}\n{"event":"broker_listening","listener":"pub`), null);
  // A broker that echoes the requested port 0 cannot be reached there.
  for (const address of ["127.0.0.1:0", "0.0.0.0:41001", "127.0.0.1:65536", "127.0.0.1", undefined]) {
    assert.throws(() => publicListeningAddress(`${event({ listener: "public", address })}\n`),
      /broker_listening must report the bound 127\.0\.0\.1 address/);
  }
});

test("accepts the exact release status", () => {
  assert.doesNotThrow(() => assertReleaseStatus(releaseStatus(), expected));
});

test("provenance verification is local by default and build service requires an explicit option", () => {
  assert.deepEqual(parseProvenanceArguments([expected.commit]), { expectedRef: expected.commit, buildService: false });
  assert.deepEqual(parseProvenanceArguments(["v1.0.0", "--build-service"]), { expectedRef: "v1.0.0", buildService: true });
  for (const args of [[], [expected.commit, "extra"], [expected.commit, "--unknown"], ["--build-service"], [expected.commit, "--build-service", "--build-service"]]) {
    assert.throws(() => parseProvenanceArguments(args), /Usage:/);
  }
  assert.throws(() => provenanceBuildPlan("HEAD", { env: {} }), /full commit object ID/);
  assert.throws(() => provenanceBuildPlan(expected.commit, { buildService: true, env: {} }), /BUILD_SERVICE_ENDPOINT is required/);
});

test("local release builds both exact-revision binaries with locked dependencies and required stamps", () => {
  const root = path.resolve("release-checkout");
  const env = {
    PATH: "/toolchain/bin",
    CARGO_TARGET_DIR: "/unrelated/cache",
    CARGO_BUILD_TARGET_DIR: "/configured/cache",
    CARGO_BUILD_TARGET: "aarch64-unknown-linux-gnu",
    BUILD_SERVICE_ENABLED: "true",
    BUILD_SERVICE_ENDPOINT: "https://build.example.test",
    AGENT_ACCESS_BUILD_COMMIT: "stale",
    AGENT_ACCESS_BUILD_PROVENANCE: "local",
    AGENT_ACCESS_REQUIRE_BUILD_PROVENANCE: "0",
  };
  const plan = provenanceBuildPlan(expected.commit, { root, env, platform: "linux", toolchain });
  assert.equal(plan.command, toolchain.cargoPath);
  assert.deepEqual(plan.args, ["--config", `build.rustc=${JSON.stringify(toolchain.rustcPath)}`,
    "--config", 'build.rustc-wrapper=""', "--config", 'build.rustc-workspace-wrapper=""',
    "build", "--release", "--locked", "--target-dir", "target", "--target", toolchain.host,
    "-p", "agent-access-broker", "-p", "agent-access"]);
  assert.equal(plan.cwd, root);
  assert.equal(plan.env.CARGO_TARGET_DIR, undefined);
  assert.equal(plan.env.CARGO_BUILD_TARGET_DIR, undefined);
  assert.equal(plan.env.CARGO_BUILD_TARGET, undefined);
  assert.equal(plan.env.RUSTC, toolchain.rustcPath);
  assert.equal(plan.env.CARGO, toolchain.cargoPath);
  assert.equal(plan.env.CARGO_BUILD_RUSTC, toolchain.rustcPath);
  for (const key of ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"]) {
    assert.equal(plan.env[key], "", `Disable ambient/configured ${key}`);
  }
  assert.equal(plan.env.BUILD_SERVICE_ENABLED, "false");
  assert.equal(plan.env.AGENT_ACCESS_BUILD_COMMIT, expected.commit);
  assert.equal(plan.env.AGENT_ACCESS_BUILD_PROVENANCE, "release");
  assert.equal(plan.env.AGENT_ACCESS_REQUIRE_BUILD_PROVENANCE, "1");
  assert.equal(plan.brokerBinary, path.join(root, "target", toolchain.host, "release", "agent-access-broker"));
  assert.equal(plan.cliBinary, path.join(root, "target", toolchain.host, "release", "agent-access"));
  assert.equal(env.CARGO_TARGET_DIR, "/unrelated/cache");
  assert.equal(env.AGENT_ACCESS_BUILD_COMMIT, "stale");
});

test("optional remote release builds forward all stamps and retain copy-back artifact paths", () => {
  const root = path.resolve("release-checkout");
  const env = { BUILD_SERVICE_ENDPOINT: "https://build.example.test", CARGO_TARGET_DIR: "/elsewhere" };
  const remote = provenanceBuildPlan(expected.commit, { root, env, buildService: true, toolchain });
  const local = provenanceBuildPlan(expected.commit, { root, env, toolchain });
  assert.equal(remote.command, "build-cli");
  assert.deepEqual(remote.args, ["build", "--endpoint", env.BUILD_SERVICE_ENDPOINT,
    "--env", `AGENT_ACCESS_BUILD_COMMIT=${expected.commit}`,
    "--env", "AGENT_ACCESS_BUILD_PROVENANCE=release",
    "--env", "AGENT_ACCESS_REQUIRE_BUILD_PROVENANCE=1", "cargo", "--",
    "build", "--release", "--locked", "--target-dir", "target", "--target", toolchain.host,
    "-p", "agent-access-broker", "-p", "agent-access"]);
  assert.equal(remote.env.BUILD_SERVICE_ENABLED, "true");
  assert.equal(remote.env.CARGO_TARGET_DIR, undefined);
  assert.equal(remote.brokerBinary, local.brokerBinary);
  assert.equal(remote.cliBinary, local.cliBinary);
  assert.equal(remote.env.RUSTC, undefined, "Local compiler path must not be claimed for a remote workspace");
  assert.ok(provenanceBuildPlan(expected.commit, { env: {}, platform: "win32", toolchain }).brokerBinary.endsWith("agent-access-broker.exe"));
});

test("rejects toolchain, compiler, flag and profile overrides without exposing their values", () => {
  for (const name of ["RUSTUP_TOOLCHAIN", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_RELEASE_LTO",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
    "RUSTC_BOOTSTRAP", "CARGO_INCREMENTAL", "CC", "HOST_CC", "TARGET_CFLAGS", "CFLAGS_x86_64_unknown_linux_gnu", "CARGO"]) {
    assert.throws(() => provenanceBuildPlan(expected.commit, { env: { [name]: "private-value" }, toolchain }),
      (error) => error.message.includes(name) && !error.message.includes("private-value"));
  }
  assert.doesNotThrow(() => assertNoToolchainOverrides({ RUSTFLAGS: "", RUSTUP_HOME: "/toolchains", CARGO_HOME: "/cargo", CARGO_BUILD_JOBS: "2" }));
  assert.throws(() => provenanceBuildPlan(expected.commit, { env: {} }), /validated local compiler and Cargo/);
});

test("checks both actual version outputs against the exact stable pin", () => {
  assert.equal(validateToolchainVersions(toolchain.pinned, toolchain.rustcVerbose, toolchain.cargoVersion), toolchain.host);
  for (const [pin, rustc, cargo] of [
    ["stable", toolchain.rustcVerbose, toolchain.cargoVersion],
    [toolchain.pinned, toolchain.rustcVerbose.replaceAll("1.98.1", "1.98.0"), toolchain.cargoVersion],
    [toolchain.pinned, toolchain.rustcVerbose, "cargo 1.99.0 (different)"],
    [toolchain.pinned, toolchain.rustcVerbose, "cargo 1.98.1-nightly (different)"],
  ]) assert.throws(() => validateToolchainVersions(pin, rustc, cargo), /must match rust-toolchain.toml/);
  assert.throws(() => validateToolchainVersions(toolchain.pinned, toolchain.rustcVerbose.replace("host:", "missing:"), toolchain.cargoVersion), /valid native host/);
});

test("resolves and rechecks actual sysroot compiler and Cargo instead of invoking mutable shims", (t) => {
  const root = temporary(t);
  writeFileSync(path.join(root, "rust-toolchain.toml"), '[toolchain]\nchannel = "1.98.1"\nprofile = "minimal"\n');
  const bin = path.join(root, "sysroot", "bin");
  mkdirSync(bin, { recursive: true });
  for (const name of ["rustc", "cargo"]) writeFileSync(path.join(bin, name), "fixture", { mode: 0o700 });
  const calls = [];
  const run = (command, args) => {
    calls.push([command, args]);
    if (args[0] === "--print") return path.dirname(bin);
    return command.endsWith("cargo") ? toolchain.cargoVersion : toolchain.rustcVerbose;
  };
  const detected = inspectLocalToolchain(root, { env: { HOME: root }, run, platform: "linux" });
  assert.equal(detected.rustcPath, path.join(bin, "rustc"));
  assert.equal(detected.cargoPath, path.join(bin, "cargo"));
  assert.equal(detected.host, toolchain.host);
  assert.deepEqual(calls, [["rustc", ["-vV"]], ["cargo", ["-V"]], ["rustc", ["--print", "sysroot"]],
    [path.join(bin, "rustc"), ["-vV"]], [path.join(bin, "cargo"), ["-V"]]]);
  assert.throws(() => inspectLocalToolchain(root, {
    env: { HOME: root }, platform: "linux",
    run: (command, args) => command === path.join(bin, "cargo") ? "cargo 1.98.1 (different build)" : run(command, args),
  }), /do not match the tools selected on PATH/);
});

test("records ancestor and Cargo-home config digests without their potentially secret contents", (t) => {
  const root = temporary(t);
  const repo = path.join(root, "repo");
  const cargoHome = path.join(root, "cargo-home");
  mkdirSync(path.join(repo, ".cargo"), { recursive: true });
  mkdirSync(cargoHome);
  const files = [path.join(repo, ".cargo", "config.toml"), path.join(cargoHome, "config"), path.join(cargoHome, "config.toml")];
  for (const file of files) writeFileSync(file, '[build]\nrustc="configured-other-compiler"\nrustc-wrapper="configured-wrapper"\nrustflags=["--cfg=custom"]\n');
  const inventory = cargoConfigInventory(repo, { CARGO_HOME: cargoHome });
  for (const file of files) {
    const recorded = inventory.find((item) => item.path === file);
    assert.match(recorded.sha256, /^[0-9a-f]{64}$/);
    assert.equal(recorded.selected, file !== path.join(cargoHome, "config.toml"));
  }
  assert.ok(!JSON.stringify(inventory).includes("configured-other-compiler"));
  const before = inventory.find((item) => item.path === files[0]).sha256;
  writeFileSync(files[0], "[build]\njobs=2\n");
  assert.notEqual(cargoConfigInventory(repo, { CARGO_HOME: cargoHome }).find((item) => item.path === files[0]).sha256, before);
});

test("symlink invocation executes argument validation instead of succeeding without running", (t) => {
  const root = temporary(t);
  const linked = path.join(root, "verify-linked.mjs");
  symlinkSync(fileURLToPath(new URL("./verify-release-provenance.mjs", import.meta.url)), linked);
  const result = spawnSync(process.execPath, [linked], { env: { ...process.env, PATH: "" }, encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Usage: node scripts\/verify-release-provenance.mjs/);
  assert.doesNotMatch(result.stderr, /spawn.*cargo|spawn.*rustc/);
});

test("entrypoint rejects Git source/index/config overrides before invoking Git or Cargo", () => {
  const script = fileURLToPath(new URL("./verify-release-provenance.mjs", import.meta.url));
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_CONFIG_COUNT"]) {
    const result = spawnSync(process.execPath, [script, expected.commit], {
      env: { ...process.env, PATH: "", [name]: "private-decoy-value" }, encoding: "utf8",
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Unset Git repository\/index\/config overrides/);
    assert.ok(result.stderr.includes(name));
    assert.ok(!result.stderr.includes("private-decoy-value"));
    assert.doesNotMatch(result.stderr, /ENOENT|spawn.*cargo|spawn.*git/);
  }
});

test("checkout validation rejects a Git core.worktree redirect before build admission", (t) => {
  const root = temporary(t);
  const decoy = temporary(t);
  const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  git("init", "--quiet");
  writeFileSync(path.join(root, "source.txt"), "release source\n");
  git("add", "source.txt");
  git("-c", "user.name=Release Fixture", "-c", "user.email=release@example.test", "commit", "--quiet", "-m", "fixture");
  const commit = git("rev-parse", "HEAD");
  assert.doesNotThrow(() => assertCleanAt(commit, "before build", { root }));
  git("config", "core.worktree", decoy);
  assert.throws(() => assertCleanAt(commit, "before build", { root }),
    /before build: Git checkout root differs from the verifier repository/);
});

test("classifies every metadata mismatch as definitive", () => {
  const unavailable = { revision: null, provenance: "unavailable" };
  const mutations = [
    (status) => { status.assembly.version = "0.2.0"; },
    (status) => { status.assembly.name = "downstream-broker"; },
    (status) => { status.assembly.source.revision = "ffffffffffffffffffffffffffffffffffffffff"; },
    (status) => { status.assembly.source = unavailable; },
    (status) => { status.assembly.source.provenance = "declared"; },
    (status) => { status.host.source = unavailable; },
    (status) => { status.host.crate = "agent-access-core"; },
    (status) => { status.sdk.version = "0.2.0"; },
    (status) => { status.sdk.source.provenance = "declared"; },
    (status) => { status.modules[1].source = unavailable; },
    (status) => { status.modules[0].source.revision = "ffffffffffffffffffffffffffffffffffffffff"; },
    (status) => { status.modules = []; },
    (status) => { delete status.modules; },
    (status) => { delete status.assembly; },
  ];
  for (const mutate of mutations) {
    const status = releaseStatus();
    mutate(status);
    assert.throws(
      () => assertReleaseStatus(status, expected),
      (error) => {
        assert.ok(error instanceof StatusMetadataMismatch);
        assert.equal(error.name, "StatusMetadataMismatch");
        assert.equal(
          error.message,
          `status mismatch: expected agent-access-broker version=${expected.version} with evidence-backed commit=${expected.commit} for the assembly, host, SDK and every module; received ${JSON.stringify(status)}`,
        );
        return true;
      },
    );
  }
  assert.throws(() => assertReleaseStatus(null, expected), StatusMetadataMismatch);
});

const CLEAN_TREE = `agent-access-broker v0.1.0 (/checkout/crates/agent-access-broker)	default
agent-access-broker-host v0.1.0 (/checkout/crates/agent-access-broker-host)	
agent-access-provider v0.1.0 (/checkout/crates/agent-access-provider)	
serde v1.0.228	default,derive,std
serde_derive v1.0.228 (proc-macro)	default
[build-dependencies]
cc v1.2.0	

agent-access v0.1.0 (/checkout/crates/agent-access)	
agent-access-provider v0.1.0 (/checkout/crates/agent-access-provider)	 (*)
`;

test("the release feature check resolves both release packages without dev units", () => {
  assert.deepEqual(releaseFeatureTreeArgs(toolchain.host), ["tree", "--locked", "--target", toolchain.host,
    "-p", "agent-access-broker", "-p", "agent-access", "-e", "normal,build", "--prefix", "none",
    "--format", "{p}\t{f}"]);
});

test("parses each unit's identity and resolved features from cargo tree output", () => {
  assert.deepEqual(parseCargoTree(CLEAN_TREE).map((pkg) => `${pkg.name}@${pkg.version}[${pkg.source}]:${pkg.features.join(",")}`), [
    "agent-access-broker@0.1.0[/checkout/crates/agent-access-broker]:default",
    "agent-access-broker-host@0.1.0[/checkout/crates/agent-access-broker-host]:",
    "agent-access-provider@0.1.0[/checkout/crates/agent-access-provider]:",
    "serde@1.0.228[null]:default,derive,std", "serde_derive@1.0.228[null]:default", "cc@1.2.0[null]:",
    "agent-access@0.1.0[/checkout/crates/agent-access]:",
  ]);
  // Units of one package with different feature sets are merged; origins are not.
  const parsed = parseCargoTree([
    "tokio v1.0.0\tio-util", "tokio v1.0.0\tmacros,rt (*)",
    "pm v0.1.0 (proc-macro) (/checkout/crates/pm)\t",
    "agent-access-jira v0.1.0 (/checkout/crates/agent-access-jira)\t",
    "agent-access-jira v0.1.0 (https://example.test/other.git?rev=v1#ffffffff)\t",
  ].join("\n"));
  assert.deepEqual(parsed, [
    { name: "tokio", version: "1.0.0", source: null, features: ["io-util", "macros", "rt"] },
    { name: "pm", version: "0.1.0", source: "/checkout/crates/pm", features: [] },
    { name: "agent-access-jira", version: "0.1.0", source: "/checkout/crates/agent-access-jira", features: [] },
    { name: "agent-access-jira", version: "0.1.0", source: "https://example.test/other.git?rev=v1#ffffffff", features: [] },
  ]);
});

test("reference crates come from workspace role metadata", () => {
  const metadata = {
    workspace_members: ["conformance-id", "fake-id"],
    packages: [
      { id: "conformance-id", name: "agent-access-conformance", metadata: { "agent-access": { role: "reference" } } },
      { id: "fake-id", name: "agent-access-fake", metadata: { "agent-access": { role: "native" } } },
      { id: "registry-id", name: "outside-reference", metadata: { "agent-access": { role: "reference" } } },
    ],
  };
  assert.deepEqual(referenceCrates(metadata), ["agent-access-conformance"]);
  assert.deepEqual(referenceCrates({}), []);
});

test("rejects any resolved test-support feature or reference crate in the release graph", () => {
  const references = ["agent-access-conformance"];
  assert.doesNotThrow(() => assertReleaseFeatureGraph(CLEAN_TREE, references));
  assert.throws(
    () => assertReleaseFeatureGraph(`${CLEAN_TREE}agent-access-provider v0.1.0 (/checkout/crates/agent-access-provider)\ttest-support (*)\nagent-access-core v0.1.0 (/checkout/crates/agent-access-core)\tdefault,test-support\n`, references),
    /Release dependency graph enables test-only code: test feature agent-access-core\/test-support, test feature agent-access-provider\/test-support$/,
  );
  assert.throws(
    () => assertReleaseFeatureGraph(`${CLEAN_TREE}agent-access-conformance v0.1.0 (/checkout/crates/agent-access-conformance)\t\n`, references),
    /enables test-only code: reference crate agent-access-conformance$/,
  );
  // A feature that merely shares the prefix is not the test-support feature.
  assert.doesNotThrow(() => assertReleaseFeatureGraph(`${CLEAN_TREE}tokio v1.0.0\ttest-support-extra\n`, references));
  assert.throws(() => assertReleaseFeatureGraph("agent-access v0.1.0 (/checkout/crates/agent-access)\t\n", references),
    /omits release package agent-access-broker$/);
  assert.throws(() => assertReleaseFeatureGraph("", references), /omits release package agent-access-broker, agent-access$/);
});

// A minimal real workspace: the provider's test-support feature reaches the
// broker only through the broker's default features, and the CLI only
// through a dev-dependency.
function featureFixture(t, { brokerDefault }) {
  const root = temporary(t);
  const write = (file, contents) => {
    mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    writeFileSync(path.join(root, file), contents);
  };
  const manifest = (name, body = "") => `[package]\nname = "${name}"\nversion = "0.1.0"\nedition = "2021"\n${body}`;
  const provider = 'agent-access-provider = { path = "../provider" }';
  write("Cargo.toml", '[workspace]\nmembers = ["broker", "cli", "provider"]\nresolver = "2"\n');
  write("broker/Cargo.toml", manifest("agent-access-broker", `\n[dependencies]\n${provider}\n`
    + (brokerDefault ? '\n[features]\ndefault = ["agent-access-provider/test-support"]\n' : "")));
  write("cli/Cargo.toml", manifest("agent-access", `\n[dependencies]\n${provider}\n\n[dev-dependencies]\n`
    + 'agent-access-provider = { path = "../provider", features = ["test-support"] }\n'));
  write("provider/Cargo.toml", manifest("agent-access-provider", "\n[features]\ntest-support = []\n"));
  for (const crate of ["broker", "cli", "provider"]) write(`${crate}/src/lib.rs`, "");
  const env = { ...process.env };
  delete env.CARGO_TARGET_DIR;
  const run = (command, args) => execFileSync(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  run("cargo", ["generate-lockfile", "--offline"]);
  const host = /^host: (\S+)$/m.exec(run("rustc", ["-vV"]))[1];
  return run("cargo", [...releaseFeatureTreeArgs(host), "--offline"]);
}

test("real cargo tree: a release root's default feature enabling test support is rejected", (t) => {
  assert.throws(() => assertReleaseFeatureGraph(featureFixture(t, { brokerDefault: true }), []),
    /enables test-only code: test feature agent-access-provider\/test-support$/);
});

test("real cargo tree: a dev-only test-support activation stays allowed", (t) => {
  const output = featureFixture(t, { brokerDefault: false });
  assert.doesNotThrow(() => assertReleaseFeatureGraph(output, []));
  assert.ok(parseCargoTree(output).some((pkg) => pkg.name === "agent-access-provider"));
});

const ROOT = "/checkout";
const TRACKED = new Set(["crates/agent-access-broker/Cargo.toml", "crates/agent-access-broker-host/Cargo.toml",
  "crates/agent-access-provider/Cargo.toml", "crates/agent-access-jira/Cargo.toml", "crates/agent-access/Cargo.toml"]);
const unit = (name, source) => `${name} v0.1.0${source ? ` (${source})` : ""}\t`;
const RELEASE_TREE = [
  unit("agent-access-broker", "/checkout/crates/agent-access-broker"),
  unit("agent-access-broker-host", "/checkout/crates/agent-access-broker-host"),
  unit("agent-access-provider", "/checkout/crates/agent-access-provider"),
  unit("agent-access-jira", "/checkout/crates/agent-access-jira"),
  "",
  unit("agent-access", "/checkout/crates/agent-access"),
  `${unit("agent-access-provider", "/checkout/crates/agent-access-provider")} (*)`,
].join("\n");
const withJira = (source) => `${RELEASE_TREE}\n${unit("agent-access-jira", source)}`;

function stampedStatus() {
  const status = releaseStatus();
  status.modules = [status.modules[1]];
  return status;
}

const sources = (tracked = TRACKED) => ({ root: ROOT, tracked, realpath: (file) => file });

test("stamped packages resolving to committed path packages in the checkout are accepted", () => {
  const origins = releasePackageOrigins(RELEASE_TREE);
  assert.deepEqual([...origins.keys()].sort(), ["agent-access 0.1.0", "agent-access-broker 0.1.0",
    "agent-access-broker-host 0.1.0", "agent-access-jira 0.1.0", "agent-access-provider 0.1.0"]);
  assert.equal(origins.get("agent-access-provider 0.1.0").length, 1, "repeated units are one origin");
  assert.doesNotThrow(() => assertStampedSources(stampedStatus(), origins, sources()));
});

test("a same-version module from another source cannot carry the qualified commit", () => {
  const tree = (source) => RELEASE_TREE.replace(unit("agent-access-jira", "/checkout/crates/agent-access-jira"),
    unit("agent-access-jira", source));
  for (const source of ["https://example.test/other.git?rev=v0.1.0#ffffffff", null, "registry `internal`",
    "/elsewhere/agent-access-jira"]) {
    assert.throws(() => assertStampedSources(stampedStatus(), releasePackageOrigins(tree(source)), sources()), (error) => {
      assert.ok(error instanceof StatusMetadataMismatch);
      assert.match(error.message, /agent-access-jira 0\.1\.0 resolves to .*, not a committed path package in the qualified checkout/);
      return true;
    });
  }
  // A path package inside the checkout that Git does not track is not committed.
  const untracked = new Set([...TRACKED].filter((file) => !file.includes("jira")));
  assert.throws(() => assertStampedSources(stampedStatus(), releasePackageOrigins(RELEASE_TREE), sources(untracked)),
    /agent-access-jira 0\.1\.0 resolves to \/checkout\/crates\/agent-access-jira, not a committed path package/);
});

test("two selected origins sharing a stamped module key are rejected, never merged", () => {
  const origins = releasePackageOrigins(withJira("https://example.test/other.git?rev=v0.1.0#ffffffff"));
  assert.equal(origins.get("agent-access-jira 0.1.0").length, 2);
  assert.throws(() => assertStampedSources(stampedStatus(), origins, sources()), (error) => {
    assert.ok(error instanceof StatusMetadataMismatch);
    assert.match(error.message, /agent-access-jira 0\.1\.0 resolves to 2 source origins \(\/checkout\/crates\/agent-access-jira, https:\/\/example\.test\/other\.git\?rev=v0\.1\.0#ffffffff\)/);
    return true;
  });
});

test("stamped packages must be among the selected release units", () => {
  const status = stampedStatus();
  status.modules.push({ crate: "agent-access-teams", version: "0.1.0", roles: [], source: status.host.source });
  assert.throws(() => assertStampedSources(status, releasePackageOrigins(RELEASE_TREE), sources()),
    /agent-access-teams 0\.1\.0 is not in the resolved release graph/);
});

// A real workspace whose stamped Jira module is a tracked path member. A second
// `agent-access-jira 0.1.0`, from a local Git repository, is an optional normal
// dependency of the SDK behind its `alt` feature. The CLI enables `alt` only
// through a dev-dependency, unless `brokerAlt` makes the broker enable it too.
function originFixture(t, { brokerAlt }) {
  const root = temporary(t);
  const write = (file, contents) => {
    mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    writeFileSync(path.join(root, file), contents);
  };
  const manifest = (name, body = "") => `[package]\nname = "${name}"\nversion = "0.1.0"\nedition = "2021"\n${body}`;
  const env = { ...process.env };
  delete env.CARGO_TARGET_DIR;
  const run = (command, args, cwd) => execFileSync(command, args, { cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  write("other/agent-access-jira/Cargo.toml", manifest("agent-access-jira"));
  write("other/agent-access-jira/src/lib.rs", "");
  const other = path.join(root, "other", "agent-access-jira");
  run("git", ["init", "--quiet"], other);
  run("git", ["add", "."], other);
  run("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "--quiet", "-m", "other"], other);
  const sdk = 'agent-access-provider = { path = "../agent-access-provider" }';
  write("ws/Cargo.toml", '[workspace]\nmembers = ["agent-access-broker", "agent-access", "agent-access-broker-host", '
    + '"agent-access-provider", "agent-access-jira"]\nresolver = "2"\n');
  write("ws/agent-access-broker/Cargo.toml", manifest("agent-access-broker", `\n[dependencies]\n${sdk}\n`
    + 'agent-access-broker-host = { path = "../agent-access-broker-host" }\n'
    + 'agent-access-jira = { path = "../agent-access-jira" }\n'
    + (brokerAlt ? '\n[features]\ndefault = ["agent-access-provider/alt"]\n' : "")));
  write("ws/agent-access/Cargo.toml", manifest("agent-access", `\n[dependencies]\n${sdk}\n\n[dev-dependencies]\n`
    + 'agent-access-provider = { path = "../agent-access-provider", features = ["alt"] }\n'));
  write("ws/agent-access-broker-host/Cargo.toml", manifest("agent-access-broker-host"));
  write("ws/agent-access-jira/Cargo.toml", manifest("agent-access-jira"));
  write("ws/agent-access-provider/Cargo.toml", manifest("agent-access-provider",
    `\n[dependencies]\njira-alt = { package = "agent-access-jira", git = "${pathToFileURL(other).href}", optional = true }\n`
    + '\n[features]\nalt = ["dep:jira-alt"]\n'));
  for (const crate of ["agent-access-broker", "agent-access", "agent-access-broker-host", "agent-access-provider", "agent-access-jira"]) {
    write(`ws/${crate}/src/lib.rs`, "");
  }
  const workspace = path.join(root, "ws");
  run("cargo", ["generate-lockfile"], workspace);
  const host = /^host: (\S+)$/m.exec(run("rustc", ["-vV"], workspace))[1];
  const output = run("cargo", releaseFeatureTreeArgs(host), workspace);
  const tracked = new Set(["agent-access-broker", "agent-access", "agent-access-broker-host", "agent-access-provider",
    "agent-access-jira"].map((crate) => `${crate}/Cargo.toml`));
  const status = releaseStatus();
  status.modules = [{ ...status.modules[1], crate: "agent-access-jira" }];
  const metadata = JSON.parse(run("cargo", ["metadata", "--locked", "--format-version", "1", "--filter-platform", host], workspace));
  return {
    check: () => assertStampedSources(status, releasePackageOrigins(output), { root: workspace, tracked }),
    metadataJiraOrigins: metadata.packages.filter((pkg) => pkg.name === "agent-access-jira").length,
  };
}

test("real cargo tree: a second module origin that only a dev feature activates is not selected", (t) => {
  const fixture = originFixture(t, { brokerAlt: false });
  // Cargo metadata's feature-enabled workspace graph still lists both origins.
  assert.equal(fixture.metadataJiraOrigins, 2);
  assert.doesNotThrow(fixture.check);
});

test("real cargo tree: two module origins selected for production are rejected", (t) => {
  assert.throws(originFixture(t, { brokerAlt: true }).check,
    /agent-access-jira 0\.1\.0 resolves to 2 source origins \(\/.*\/ws\/agent-access-jira, file:\/\/.*\/other\/agent-access-jira#[0-9a-f]{8}\)/);
});
