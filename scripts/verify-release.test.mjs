import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { REQUIRED_RELEASE_CHECKS, validateQualification } from "./release-qualification.mjs";
import { assertNoGitOverrides } from "./release-environment.mjs";
import { assertQualificationSource, assertUnixSignalTestExecuted, parseQualificationArguments, qualificationOutputDirectory,
  qualificationPlan, runQualification } from "./verify-release.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const commit = "a".repeat(40);
const version = "0.1.0";
const nativeTarget = "x86_64-unknown-linux-gnu";
const qualified = () => ({ schemaVersion: 1, status: "passed", sourceClean: true, commit, version,
  platform: "linux", target: nativeTarget, startedAt: "2026-10-10T01:00:00.000Z", finishedAt: "2026-10-10T02:00:00.000Z",
  checks: REQUIRED_RELEASE_CHECKS.map((id) => ({ id, status: "passed", exitCode: 0, command: ["checked-command"] })) });
const temporary = (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), "broker-qualification-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
};

test("the Unix signal gate rejects a successful zero-match run or an ignored parent", () => {
  const summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 0.01s\n";
  assert.doesNotThrow(() => assertUnixSignalTestExecuted(`running 1 test\ntest tests::unix_signal_smoke_in_isolated_child_processes ... ok\n${summary}`));
  for (const output of [
    "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 33 filtered out; finished in 0.00s\n",
    "running 1 test\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 32 filtered out; finished in 0.00s\n",
    "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 32 filtered out; finished in 0.01s\n",
    `${summary}${summary}`, "",
  ]) assert.throws(() => assertUnixSignalTestExecuted(output), /exactly one passing parent test/);
});

test("publication rejects stale, failed, incomplete, duplicate, and skipped qualification evidence", () => {
  assert.equal(validateQualification(qualified(), { commit, version }).commit, commit);
  const corruptions = [
    (report) => { report.commit = "b".repeat(40); },
    (report) => { report.version = "0.2.0"; },
    (report) => { report.status = "failed"; },
    (report) => { report.sourceClean = false; },
    (report) => { report.checks.pop(); },
    (report) => { report.checks[0] = report.checks[1]; },
    (report) => { report.checks[0].exitCode = 1; },
    (report) => { report.checks[0].status = "skipped"; },
    (report) => { report.checks[0].command = []; },
    (report) => { report.finishedAt = "2026-10-09T02:00:00.000Z"; },
  ];
  for (const corrupt of corruptions) {
    const report = qualified();
    corrupt(report);
    assert.throws(() => validateQualification(report, { commit, version }));
  }
  const windows = qualified();
  windows.platform = "win32";
  windows.target = "x86_64-pc-windows-msvc";
  Object.assign(windows.checks.find((check) => check.id === "unix-signals"), { status: "not-applicable", exitCode: null });
  validateQualification(windows, { commit, version });
  windows.platform = "linux";
  assert.throws(() => validateQualification(windows, { commit, version }), /unix-signals/);
});

test("qualification preserves prior evidence and refuses paths inside the checkout, including symlinks", (t) => {
  const directory = temporary(t);
  const checkout = path.join(directory, "checkout");
  mkdirSync(checkout);
  const output = path.join(directory, "evidence");
  assert.equal(qualificationOutputDirectory(checkout, output), output);
  assert.throws(() => qualificationOutputDirectory(checkout, "relative"), /absolute/);
  assert.throws(() => qualificationOutputDirectory(checkout, path.join(checkout, "ignored-output")), /outside/);
  const alias = path.join(directory, "checkout-alias");
  symlinkSync(checkout, alias, process.platform === "win32" ? "junction" : "dir");
  assert.throws(() => qualificationOutputDirectory(checkout, path.join(alias, "new-output")), /outside/);
  mkdirSync(output);
  writeFileSync(path.join(output, "earlier.log"), "keep this evidence");
  assert.throws(() => qualificationOutputDirectory(checkout, output), /preserve earlier evidence/);
  assert.equal(readFileSync(path.join(output, "earlier.log"), "utf8"), "keep this evidence");
  assert.deepEqual(parseQualificationArguments(["--output-dir", output]), { outputDir: output });
  for (const args of [[], ["--output-dir", "relative"], ["--skip-browser", output]]) {
    assert.throws(() => parseQualificationArguments(args), /Usage/);
  }
});

test("qualification uses required native/browser gates and fresh paths without publication commands", (t) => {
  const outputDir = temporary(t);
  const plan = qualificationPlan({ root, outputDir, commit, target: nativeTarget, platform: "linux" });
  assert.equal(plan.length, REQUIRED_RELEASE_CHECKS.length);
  for (const id of ["rust-tests", "rust-build", "rust-clippy", "unix-signals"]) {
    const check = plan.find((entry) => entry.id === id);
    assert.ok(check.command.includes("--locked"));
    assert.equal(check.command[check.command.indexOf("--target") + 1], nativeTarget);
    assert.equal(check.command[check.command.indexOf("--target-dir") + 1], "target");
  }
  const boundaries = plan.find((entry) => entry.id === "crate-boundaries");
  assert.deepEqual(boundaries.command, [process.execPath, "scripts/check-crate-boundaries.mjs"]);
  assert.equal(boundaries.cargo, true);
  const browser = plan.find((entry) => entry.id === "portal-browser");
  assert.equal(browser.binaries.brokerBinary, path.join(root, "target", nativeTarget, "debug", "agent-access-broker"));
  assert.ok(plan.find((entry) => entry.id === "browser-prerequisites").command.at(-1).includes("chromium.launch"));
  assert.ok(plan.find((entry) => entry.id === "release-provenance").command.includes(commit));
  assert.ok(plan.every((entry) => !entry.command.some((argument) => argument === "gh" || argument === "push" || argument === "tag")));
  const windows = qualificationPlan({ root, outputDir, commit, target: "x86_64-pc-windows-msvc", platform: "win32" });
  assert.equal(windows.filter((entry) => entry.notApplicable).map((entry) => entry.id).join(","), "unix-signals");
  assert.deepEqual(windows.find((entry) => entry.id === "portal-dependencies").command, ["cmd.exe", "/d", "/s", "/c", "npm --prefix apps/portal ci"]);
});

test("qualification detects a changed or dirty source and retains a failed report without running gates", (t) => {
  const directory = temporary(t);
  const checkout = path.join(directory, "checkout");
  mkdirSync(checkout);
  const git = (...args) => execFileSync("git", args, { cwd: checkout, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  git("init");
  writeFileSync(path.join(checkout, "source.txt"), "committed\n");
  git("add", "source.txt");
  git("-c", "user.name=Qualification Test", "-c", "user.email=qualification@example.test", "commit", "-m", "fixture");
  const revision = git("rev-parse", "HEAD");
  assertQualificationSource(checkout, revision);
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
    "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_GLOBAL", "GIT_OBJECT_DIRECTORY"]) {
    assert.throws(() => assertQualificationSource(checkout, revision, { ...process.env, [name]: "decoy-or-secret" }), /Git repository\/index\/config overrides/);
    try { assertNoGitOverrides({ [name]: "decoy-or-secret" }); }
    catch (error) { assert.ok(!error.message.includes("decoy-or-secret")); }
  }
  assert.throws(() => assertQualificationSource(checkout, commit), /same clean commit/);
  writeFileSync(path.join(checkout, "source.txt"), "uncommitted\n");
  assert.throws(() => assertQualificationSource(checkout, revision), /same clean commit/);
  const outputDir = path.join(directory, "failed-evidence");
  assert.throws(() => runQualification({ root: checkout, outputDir }), /same clean commit/);
  const report = JSON.parse(readFileSync(path.join(outputDir, "qualification.json"), "utf8"));
  assert.equal(report.status, "failed");
  assert.equal(report.commit, revision);
  assert.equal(report.sourceClean, false);
  assert.deepEqual(report.checks, []);
  assert.equal(readFileSync(path.join(checkout, "source.txt"), "utf8"), "uncommitted\n");
  assert.throws(() => validateQualification(report, { commit: revision, version }));
});
