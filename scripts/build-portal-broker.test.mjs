import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { portalBuildPlan } from "./build-portal-broker.mjs";
import { parseRustcHost, portalBinaries, repositoryBinaries } from "./portal-binaries.mjs";

const root = path.resolve("portal-checkout");
const target = "x86_64-unknown-linux-gnu";

test("portal builders and fixtures select the same repository artifacts despite target overrides", () => {
  for (const enabled of ["false", "true"]) {
    const env = { BUILD_SERVICE_ENABLED: enabled, CARGO_TARGET_DIR: "/external/cache", CARGO_BUILD_TARGET_DIR: "/config/environment", CARGO_BUILD_TARGET: "aarch64-unknown-linux-gnu" };
    const plan = portalBuildPlan(root, env, "linux", target);
    const cargoArgs = enabled === "true" ? plan.args.slice(3) : plan.args;
    // The explicit Cargo option overrides both environment and .cargo/config.toml.
    assert.deepEqual(cargoArgs, ["build", "--locked", "--target-dir", "target", "--target", target, "-p", "agent-access-broker", "-p", "agent-access"]);
    assert.equal(plan.command, enabled === "true" ? "build-cli" : "cargo");
    assert.equal(plan.cwd, root);
    assert.equal(plan.env.CARGO_TARGET_DIR, undefined);
    assert.equal(env.CARGO_TARGET_DIR, "/external/cache");
    assert.deepEqual(plan.binaries, portalBinaries(root, env, "linux", target));
    assert.equal(plan.binaries.brokerBinary, path.join(root, "target", target, "debug", "agent-access-broker"));
    assert.equal(plan.binaries.cliBinary, path.join(root, "target", target, "debug", "agent-access"));
  }
});

test("each explicit binary override is preserved and only missing packages are built", () => {
  const broker = "/release/bin/agent-access-broker";
  const cli = "/release/bin/agent-access";
  const brokerOnly = portalBuildPlan(root, { AAB_BROKER_BIN: broker }, "linux", target);
  assert.equal(brokerOnly.binaries.brokerBinary, broker);
  assert.deepEqual(brokerOnly.args.slice(-2), ["-p", "agent-access"]);
  assert.ok(!brokerOnly.args.includes("agent-access-broker"));
  const cliOnly = portalBuildPlan(root, { AAB_CLI_BIN: cli }, "linux", target);
  assert.equal(cliOnly.binaries.cliBinary, cli);
  assert.deepEqual(cliOnly.args.slice(-2), ["-p", "agent-access-broker"]);
  assert.ok(!cliOnly.args.includes("agent-access"));
  const both = portalBuildPlan(root, { AAB_BROKER_BIN: broker, AAB_CLI_BIN: cli, AAB_PORTAL_DIST: "/release/portal" });
  assert.equal(both.command, null);
  assert.deepEqual(both.binaries, { brokerBinary: broker, cliBinary: cli, portalDist: "/release/portal" });
  assert.ok(portalBinaries(root, {}, "win32", "x86_64-pc-windows-msvc").cliBinary.endsWith("agent-access.exe"));
});

test("native artifacts require the rustc host and never fall back to a targetless path", () => {
  assert.equal(parseRustcHost(`rustc 1.98.1\nhost: ${target}\nrelease: 1.98.1\n`), target);
  assert.equal(parseRustcHost("rustc 1.98.1\r\nhost: x86_64-pc-windows-msvc\r\n"), "x86_64-pc-windows-msvc");
  for (const output of ["rustc 1.98.1", "host: ../target", "host: "]) {
    assert.throws(() => parseRustcHost(output), /valid native host target/);
  }
  for (const value of [undefined, "", "../target"]) {
    assert.throws(() => repositoryBinaries(root, "debug", value), /native Rust target is required/);
  }
});

test("prebuilt entrypoint validates both executable overrides without invoking a build", () => {
  const temporary = mkdtempSync(path.join(tmpdir(), "portal-build-test-"));
  try {
    const script = fileURLToPath(new URL("./build-portal-broker.mjs", import.meta.url));
    const env = { ...process.env, PATH: "", AAB_BROKER_BIN: process.execPath, AAB_CLI_BIN: process.execPath };
    const valid = spawnSync(process.execPath, [script], { env, encoding: "utf8" });
    assert.equal(valid.status, 0, valid.stderr);
    assert.match(valid.stderr, /using prebuilt AAB_CLI_BIN/);
    for (const name of ["AAB_BROKER_BIN", "AAB_CLI_BIN"]) {
      const invalid = spawnSync(process.execPath, [script], { env: { ...env, [name]: temporary }, encoding: "utf8" });
      assert.equal(invalid.status, 1);
      assert.match(invalid.stderr, new RegExp(`${name} is not an executable file`));
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("portal entrypoint runs through a symlinked directory without requiring Rust for prebuilt binaries", () => {
  const temporary = mkdtempSync(path.join(tmpdir(), "portal-symlink-test-"));
  try {
    const scripts = fileURLToPath(new URL(".", import.meta.url));
    const alias = path.join(temporary, "scripts-alias");
    symlinkSync(scripts, alias, process.platform === "win32" ? "junction" : "dir");
    const script = path.join(alias, "build-portal-broker.mjs");
    const env = { ...process.env, PATH: "", AAB_BROKER_BIN: process.execPath, AAB_CLI_BIN: process.execPath };
    const valid = spawnSync(process.execPath, [script], { env, encoding: "utf8" });
    assert.equal(valid.status, 0, valid.stderr);
    assert.match(valid.stderr, /using prebuilt AAB_CLI_BIN/);
    const invalid = spawnSync(process.execPath, [script], { env: { ...env, AAB_CLI_BIN: temporary }, encoding: "utf8" });
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /AAB_CLI_BIN is not an executable file/);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
