import path from "node:path";
import { execFileSync } from "node:child_process";

// Build commands run from the repository root and explicitly select this
// relative directory, including inside the optional build-service workspace.
export const CARGO_TARGET_DIRECTORY = "target";

export function parseRustcHost(output) {
  const host = /^host: ([a-zA-Z0-9_]+(?:-[a-zA-Z0-9_]+)+)\r?$/m.exec(output)?.[1];
  if (!host) throw new Error("rustc -vV did not report a valid native host target");
  return host;
}

export function nativeBuildTarget(repoRoot, env = process.env) {
  return parseRustcHost(execFileSync("rustc", ["-vV"], {
    cwd: repoRoot, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  }));
}

export function repositoryBinaries(repoRoot, profile, target, platform = process.platform) {
  if (!/^[a-zA-Z0-9_]+(?:-[a-zA-Z0-9_]+)+$/.test(target ?? "")) {
    throw new Error("A native Rust target is required to select repository binaries");
  }
  const suffix = platform === "win32" ? ".exe" : "";
  const directory = path.join(repoRoot, CARGO_TARGET_DIRECTORY, target, profile);
  return {
    brokerBinary: path.join(directory, `agent-access-broker${suffix}`),
    cliBinary: path.join(directory, `agent-access${suffix}`),
  };
}

export function portalBinaries(repoRoot, env = process.env, platform = process.platform, target) {
  // Fully prebuilt browser runs require neither Cargo nor rustc on the host.
  const defaults = env.AAB_BROKER_BIN && env.AAB_CLI_BIN ? {}
    : repositoryBinaries(repoRoot, "debug", target ?? nativeBuildTarget(repoRoot, env), platform);
  return {
    brokerBinary: env.AAB_BROKER_BIN || defaults.brokerBinary,
    cliBinary: env.AAB_CLI_BIN || defaults.cliBinary,
    portalDist: env.AAB_PORTAL_DIST || path.join(repoRoot, "apps", "portal", "dist"),
  };
}
