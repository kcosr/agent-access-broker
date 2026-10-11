#!/usr/bin/env node
// Qualify one clean native candidate. This command never tags or publishes.
import { execFileSync, spawnSync } from "node:child_process";
import { accessSync, closeSync, constants, existsSync, mkdirSync, openSync,
  readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { repositoryBinaries } from "./portal-binaries.mjs";
import { assertNoGitOverrides } from "./release-environment.mjs";
import { REQUIRED_RELEASE_CHECKS, validateQualification } from "./release-qualification.mjs";
import { inspectLocalToolchain, provenanceBuildPlan } from "./verify-release-provenance.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const ROOT = resolve(dirname(SCRIPT_PATH), "..");
const PROVENANCE_VARIABLES = ["AGENT_ACCESS_BUILD_COMMIT", "AGENT_ACCESS_BUILD_PROVENANCE", "AGENT_ACCESS_REQUIRE_BUILD_PROVENANCE"];
const stamp = () => new Date().toISOString();

function npmCommand(platform, ...args) {
  // All npm arguments here are fixed repository commands. Windows .cmd files
  // need cmd.exe; never interpolate caller-supplied values into this string.
  return platform === "win32" ? ["cmd.exe", "/d", "/s", "/c", ["npm", ...args].join(" ")]
    : ["npm", ...args];
}

export function parseQualificationArguments(args) {
  if (args.length !== 2 || args[0] !== "--output-dir" || !isAbsolute(args[1])) {
    throw new Error("Usage: node scripts/verify-release.mjs --output-dir /absolute/external/directory");
  }
  return { outputDir: args[1] };
}

export function qualificationOutputDirectory(root, requested) {
  if (!isAbsolute(requested)) throw new Error("Qualification output directory must be absolute");
  const tail = [];
  let ancestor = resolve(requested);
  while (!existsSync(ancestor)) {
    tail.unshift(basename(ancestor));
    ancestor = dirname(ancestor);
  }
  const output = resolve(realpathSync(ancestor), ...tail);
  const fromRoot = relative(realpathSync(root), output);
  if (!fromRoot || (fromRoot !== ".." && !fromRoot.startsWith(`..${sep}`) && !isAbsolute(fromRoot))) {
    throw new Error("Qualification output must be outside the source checkout");
  }
  if (existsSync(output) && readdirSync(output).length) {
    throw new Error("Qualification output directory must be new or empty; preserve earlier evidence");
  }
  return output;
}

export function qualificationPlan({ root, outputDir, commit, target, platform = process.platform,
  cargo = "cargo", compilerArgs = [], node = process.execPath }) {
  const python = "python3";
  const cargoCommand = (...args) => [cargo, ...compilerArgs, ...args];
  const native = ["--locked", "--target-dir", "target", "--target", target];
  const binaries = repositoryBinaries(root, "debug", target, platform);
  const noticeDirectory = join(outputDir, "rust-notices");
  const nodeTests = readdirSync(join(root, "scripts")).filter((file) => file.endsWith(".test.mjs"))
    .sort().map((file) => `scripts/${file}`);
  const portal = (...args) => npmCommand(platform, "--prefix", "apps/portal", "run", ...args);
  const browserProbe = "import {chromium} from './apps/portal/node_modules/playwright/index.mjs'; "
    + "const browser = await chromium.launch({headless:true}); "
    + "console.log(JSON.stringify({chromium:browser.version(),headlessLaunch:'passed'})); await browser.close();";
  const checks = [
    { id: "portal-dependencies", command: npmCommand(platform, "--prefix", "apps/portal", "ci") },
    { id: "browser-prerequisites", command: [node, "--input-type=module", "-e", browserProbe] },
    { id: "node-tests", command: [node, "--test", ...nodeTests] },
    { id: "rust-notice-tests", command: [python, "-B", "scripts/generate-rust-notices.test.py"] },
    { id: "release-prerequisite-tests", command: [python, "-B", "scripts/release-prerequisites.test.py"] },
    { id: "launcher-tests", command: [python, "-B", "scripts/local-broker-process.test.py"] },
    { id: "audit-demo-tests", command: [python, "-B", "demo/seed-audit-showcase.test.py"] },
    { id: "doc-links", command: [node, "scripts/check-doc-links.mjs"] },
    { id: "rust-format", command: cargoCommand("fmt", "--check"), cargo: true },
    { id: "portal-unit", command: portal("test:unit") },
    { id: "portal-build", command: portal("build") },
    { id: "rust-tests", command: cargoCommand("test", ...native, "--workspace", "--no-fail-fast", "--", "--test-threads=4"), cargo: true },
    { id: "rust-build", command: cargoCommand("build", ...native, "-p", "agent-access-broker", "-p", "agent-access"), cargo: true },
    { id: "rust-clippy", command: cargoCommand("clippy", ...native, "--all-targets", "--all-features", "--", "-D", "warnings"), cargo: true },
    { id: "unix-signals", command: cargoCommand("test", ...native, "-p", "agent-access-broker", "--bin", "agent-access-broker",
      "tests::unix_signal_smoke_in_isolated_child_processes", "--", "--ignored", "--exact", "--color=never"), cargo: true, notApplicable: platform === "win32" },
    { id: "broker-sample", command: [binaries.brokerBinary, "--config", "agent-access-broker.sample.toml", "config", "validate"] },
    { id: "broker-production-sample", command: [binaries.brokerBinary, "--config", "agent-access-broker.production.sample.toml", "config", "validate"] },
    { id: "cli-sample", command: [binaries.cliBinary, "--config", "agent-access.sample.toml", "config", "validate"] },
    { id: "portal-browser", command: portal("test:e2e"), binaries },
    { id: "release-provenance", command: [node, "scripts/verify-release-provenance.mjs", commit] },
    { id: "rust-notices-generate", command: [python, "-B", "scripts/generate-rust-notices.py", "--target", target, "--output-dir", noticeDirectory] },
    { id: "rust-notices-check", command: [python, "-B", "scripts/generate-rust-notices.py", "--target", target, "--output-dir", noticeDirectory, "--check"] },
  ];
  if (JSON.stringify(checks.map((check) => check.id).sort()) !== JSON.stringify([...REQUIRED_RELEASE_CHECKS].sort())) {
    throw new Error("Qualification plan does not match the required release checks");
  }
  return checks;
}

function capture(root, command, args, env) {
  return execFileSync(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

export function assertQualificationSource(root, commit, env = process.env) {
  assertNoGitOverrides(env);
  if (realpathSync(capture(root, "git", ["rev-parse", "--show-toplevel"], env)) !== realpathSync(root)
      || capture(root, "git", ["rev-parse", "HEAD"], env) !== commit
      || capture(root, "git", ["status", "--porcelain", "--untracked-files=all"], env)) {
    throw new Error("Qualification requires the same clean commit throughout every check");
  }
}

export function assertUnixSignalTestExecuted(output) {
  const summaries = output.match(/^test result:.*$/gm) ?? [];
  if (summaries.length !== 1 || !/^test result: ok\. 1 passed; 0 failed; 0 ignored;/.test(summaries[0])) {
    throw new Error("The required Unix signal gate must execute exactly one passing parent test");
  }
}

export function runQualification({ root = ROOT, outputDir, env = process.env } = {}) {
  const directory = qualificationOutputDirectory(root, outputDir);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const reportFile = join(directory, "qualification.json");
  const report = { schemaVersion: 1, status: "running", sourceClean: false,
    commit: null, version: null, platform: process.platform, target: null,
    startedAt: stamp(), finishedAt: null, checks: [],
    scope: "Native local standalone Broker/CLI/portal qualification; this is an operator evidence record, not a signed attestation.",
    exclusions: [
      "Ignored live-provider smokes and administrator deployment/backup acceptance are not run.",
      "Cross-repository ingress and screening stacks are not part of standalone qualification.",
      "Browser tests mix real-service fixtures and mocked UI contracts; optional delegated OAuth runs only when OAUTH_STUB_REPO is configured.",
      "Native host results do not establish cross-platform, other Linux distribution, or hermetic-build guarantees.",
      "No runtime archive is assembled; package extraction/checksum acceptance remains a distribution gate.",
    ],
    delegatedOAuthFixture: env.OAUTH_STUB_REPO ? "configured; see browser log for outcome" : "not configured; optional browser fixture skipped",
  };
  const save = () => writeFileSync(reportFile, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  save();
  try {
    const baseEnv = { ...env, BUILD_SERVICE_ENABLED: "false", CARGO_BUILD_JOBS: env.CARGO_BUILD_JOBS || "4" };
    for (const name of ["CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_TARGET", ...PROVENANCE_VARIABLES]) delete baseEnv[name];
    assertNoGitOverrides(baseEnv);
    report.commit = capture(root, "git", ["rev-parse", "HEAD"], baseEnv);
    assertQualificationSource(root, report.commit, baseEnv);
    const toolchain = inspectLocalToolchain(root, { env: baseEnv });
    report.target = toolchain.host;
    const npmVersionCommand = npmCommand(process.platform, "--version");
    report.prerequisites = JSON.parse(capture(root, "python3", ["-B", "scripts/release-prerequisites.py",
      ...toolchain.cargoConfigs.filter((config) => config.selected).flatMap((config) => ["--cargo-config", config.path])], baseEnv));
    report.toolchain = { ...toolchain, node: process.version,
      npm: capture(root, npmVersionCommand[0], npmVersionCommand.slice(1), baseEnv),
      python: capture(root, "python3", ["--version"], baseEnv),
    };
    const provenancePlan = provenanceBuildPlan(report.commit, { root, env: baseEnv, toolchain });
    const cargoEnv = { ...provenancePlan.env };
    for (const name of PROVENANCE_VARIABLES) delete cargoEnv[name];
    const metadata = JSON.parse(capture(root, toolchain.cargoPath, ["metadata", "--locked", "--no-deps", "--format-version", "1"], cargoEnv));
    report.version = metadata.packages.find((entry) => entry.name === "agent-access-broker")?.version;
    if (!report.version || metadata.packages.some((entry) => metadata.workspace_members.includes(entry.id) && entry.version !== report.version)) {
      throw new Error("All workspace packages must share the Broker release version");
    }
    const compilerArgs = provenancePlan.args.slice(0, provenancePlan.args.indexOf("build"));
    const checks = qualificationPlan({ root, outputDir: directory, commit: report.commit,
      target: toolchain.host, cargo: toolchain.cargoPath, compilerArgs });
    for (const check of checks) {
      assertQualificationSource(root, report.commit, baseEnv);
      const result = { id: check.id, status: "running", command: check.command,
        startedAt: stamp(), finishedAt: null, exitCode: null, log: `${check.id}.log` };
      report.checks.push(result);
      save();
      if (check.notApplicable) {
        result.status = "not-applicable";
        result.finishedAt = stamp();
        writeFileSync(join(directory, result.log), "Unix signal fixture is not applicable on Windows.\n");
        save();
        continue;
      }
      console.log(`Qualification: ${check.id}`);
      const checkEnv = { ...(check.cargo ? cargoEnv : baseEnv) };
      if (check.binaries) {
        accessSync(check.binaries.brokerBinary, constants.X_OK);
        accessSync(check.binaries.cliBinary, constants.X_OK);
        Object.assign(checkEnv, { AAB_BROKER_BIN: check.binaries.brokerBinary,
          AAB_CLI_BIN: check.binaries.cliBinary, AAB_PORTAL_DIST: join(root, "apps", "portal", "dist") });
      }
      const log = openSync(join(directory, result.log), "w", 0o600);
      try {
        const execution = spawnSync(check.command[0], check.command.slice(1), {
          cwd: root, env: checkEnv, stdio: ["ignore", log, log],
        });
        result.exitCode = execution.status;
        if (execution.error) result.error = execution.error.message;
        if (execution.signal) result.signal = execution.signal;
        result.status = execution.status === 0 && !execution.error ? "passed" : "failed";
        if (result.status === "passed" && check.id === "unix-signals") {
          try { assertUnixSignalTestExecuted(readFileSync(join(directory, result.log), "utf8")); }
          catch (error) { result.status = "failed"; result.error = error.message; }
        }
      } finally {
        closeSync(log);
        result.finishedAt = stamp();
        save();
      }
      if (result.status !== "passed") throw new Error(`Required check failed: ${check.id}; see ${join(directory, result.log)}`);
      assertQualificationSource(root, report.commit, baseEnv);
      console.log(`Passed: ${check.id}`);
    }
    assertQualificationSource(root, report.commit, baseEnv);
    report.sourceClean = true;
    report.status = "passed";
    report.finishedAt = stamp();
    validateQualification(report, { commit: report.commit, version: report.version });
    save();
    console.log(`Qualified ${report.version} at ${report.commit}: ${reportFile}`);
    return report;
  } catch (error) {
    report.status = "failed";
    report.finishedAt = stamp();
    report.error = error.message;
    const running = report.checks.find((check) => check.status === "running");
    if (running) Object.assign(running, { status: "failed", finishedAt: stamp(), error: error.message });
    save();
    throw error;
  }
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH)) {
  try { runQualification(parseQualificationArguments(process.argv.slice(2))); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
