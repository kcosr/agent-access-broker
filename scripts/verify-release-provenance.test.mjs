import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import {
  StatusMetadataMismatch,
  assertReleaseStatus,
  assertCleanAt,
  assertNoToolchainOverrides,
  cargoConfigInventory,
  inspectLocalToolchain,
  parseProvenanceArguments,
  provenanceBuildPlan,
  validateToolchainVersions,
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

test("accepts the exact release status", () => {
  assert.doesNotThrow(() =>
    assertReleaseStatus(
      {
        brokerVersion: expected.version,
        buildCommit: expected.commit,
        buildProvenance: "release",
        catalogVersion: "agent-access.catalog.v2",
        sendSchemaVersion: "agent-access.send.v1",
      },
      expected,
    ),
  );
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
  for (const status of [
    {
      brokerVersion: "0.2.0",
      buildCommit: expected.commit,
      buildProvenance: "release",
    },
    {
      brokerVersion: expected.version,
      buildCommit: "ffffffffffffffffffffffffffffffffffffffff",
      buildProvenance: "release",
    },
    {
      brokerVersion: expected.version,
      buildCommit: expected.commit,
      buildProvenance: "unavailable",
    },
  ]) {
    assert.throws(
      () => assertReleaseStatus(status, expected),
      (error) => {
        assert.ok(error instanceof StatusMetadataMismatch);
        assert.equal(error.name, "StatusMetadataMismatch");
        assert.equal(
          error.message,
          `status mismatch: expected version=${expected.version} commit=${expected.commit} provenance=release; received ${JSON.stringify(status)}`,
        );
        return true;
      },
    );
  }
});
