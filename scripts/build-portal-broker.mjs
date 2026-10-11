#!/usr/bin/env node
import { spawn } from "node:child_process";
import { accessSync, constants, existsSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { CARGO_TARGET_DIRECTORY, nativeBuildTarget, portalBinaries } from "./portal-binaries.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(scriptPath), "..");

export function portalBuildPlan(root, env = process.env, platform = process.platform, target) {
  const nativeTarget = env.AAB_BROKER_BIN && env.AAB_CLI_BIN ? null
    : target ?? nativeBuildTarget(root, env);
  const binaries = portalBinaries(root, env, platform, nativeTarget);
  const overrides = [
    ["AAB_BROKER_BIN", binaries.brokerBinary],
    ["AAB_CLI_BIN", binaries.cliBinary],
  ].filter(([name]) => env[name]);
  const packages = [];
  if (!env.AAB_BROKER_BIN) packages.push("agent-access-broker");
  if (!env.AAB_CLI_BIN) packages.push("agent-access");
  const buildService = /^(1|true|yes|on)$/i.test(env.BUILD_SERVICE_ENABLED ?? "");
  const cargoArgs = ["build", "--locked", "--target-dir", CARGO_TARGET_DIRECTORY,
    ...(nativeTarget ? ["--target", nativeTarget] : []),
    ...packages.flatMap((name) => ["-p", name])];
  const buildEnv = { ...env };
  delete buildEnv.CARGO_TARGET_DIR;
  return {
    binaries,
    target: nativeTarget,
    overrides,
    command: packages.length ? (buildService ? "build-cli" : "cargo") : null,
    args: buildService ? ["build", "cargo", "--", ...cargoArgs] : cargoArgs,
    cwd: root,
    env: buildEnv,
  };
}

async function main() {
  const plan = portalBuildPlan(repoRoot);
  for (const [name, binary] of plan.overrides) {
    try {
      accessSync(binary, constants.X_OK);
      if (!statSync(binary).isFile()) throw new Error("not a file");
    } catch {
      throw new Error(`${name} is not an executable file: ${binary}`);
    }
    console.error(`[portal-e2e] using prebuilt ${name}: ${binary}`);
  }
  if (!plan.command) return;
  console.error(`[portal-e2e] building portal fixture binaries for ${plan.target} with ${plan.command}`);
  const child = spawn(plan.command, plan.args, {
    cwd: plan.cwd,
    env: plan.env,
    stdio: "inherit",
  });
  await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`${plan.command} exited with code ${code ?? "null"}, signal ${signal ?? "none"}`));
    });
  });
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(scriptPath)) {
  try {
    await main();
  } catch (error) {
    console.error(`[portal-e2e] ${error.message}`);
    process.exitCode = 1;
  }
}
