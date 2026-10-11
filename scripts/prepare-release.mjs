#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { nextCycleChangelog, prepareChangelog, preparedRelease, prepareVersionFiles, releaseVersion, workspaceVersion } from "./release-plan.mjs";
import { assertNoGitOverrides } from "./release-environment.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FILES = ["Cargo.toml", "Cargo.lock", "CHANGELOG.md"];
const METADATA = ["metadata", "--locked", "--no-deps", "--format-version", "1"];

function workspacePackages(metadata, version) {
  if (!Array.isArray(metadata.workspace_members) || !metadata.workspace_members.length || !Array.isArray(metadata.packages)) {
    throw new Error("Cargo metadata must identify workspace packages");
  }
  return metadata.workspace_members.map((id) => {
    const member = metadata.packages.find((entry) => entry.id === id);
    if (!member || member.version !== version || typeof member.name !== "string") {
      throw new Error(`Every workspace package must use version ${version}`);
    }
    return member.name;
  });
}

/** Prepare only the three release files; callers review and commit the result. */
export function prepareRelease(argument, {
  root = ROOT,
  env = process.env,
  date = new Date().toISOString().slice(0, 10),
  run = (command, args) => execFileSync(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }),
} = {}) {
  if (!argument) throw new Error("Usage: node scripts/prepare-release.mjs <current|major|minor|patch|X.Y.Z>");
  assertNoGitOverrides(env);
  if (realpathSync(run("git", ["rev-parse", "--show-toplevel"]).trim()) !== realpathSync(root)) {
    throw new Error("Release preparation source directory must be the Git repository root");
  }
  if (run("git", ["status", "--porcelain"]).trim()) throw new Error("Release preparation requires a clean worktree");
  const head = run("git", ["rev-parse", "HEAD"]).trim();
  const original = FILES.map((file) => readFileSync(join(root, file)));
  const current = workspaceVersion(original[0].toString());
  const version = releaseVersion(current, argument);
  const changelog = nextCycleChangelog(prepareChangelog(original[2].toString(), version, date).content);
  const release = preparedRelease(changelog, version);
  const names = workspacePackages(JSON.parse(run("cargo", METADATA)), current);
  const updated = prepareVersionFiles(original[0].toString(), original[1].toString(), names, version);
  const contents = [updated.manifest, updated.lock, changelog];
  if (run("git", ["status", "--porcelain"]).trim() || run("git", ["rev-parse", "HEAD"]).trim() !== head) {
    throw new Error("Checkout changed during release preparation preflight");
  }
  try {
    FILES.forEach((file, index) => writeFileSync(join(root, file), contents[index]));
    const verifiedNames = workspacePackages(JSON.parse(run("cargo", METADATA)), version);
    if (JSON.stringify([...verifiedNames].sort()) !== JSON.stringify([...names].sort())) throw new Error("Workspace membership changed during preparation");
  } catch (error) {
    const failures = [];
    FILES.forEach((file, index) => {
      try { writeFileSync(join(root, file), original[index]); } catch (restoreError) { failures.push(`${file}: ${restoreError.message}`); }
    });
    throw new Error(`Release preparation failed; ${failures.length ? `rollback failed for ${failures.join("; ")}` : "all three release files restored"}. ${error.message}`);
  }
  return release;
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    if (process.argv.length !== 3) throw new Error("Usage: node scripts/prepare-release.mjs <current|major|minor|patch|X.Y.Z>");
    const release = prepareRelease(process.argv[2]);
    console.log(`Prepared ${release.tag}. Review and commit Cargo.toml, Cargo.lock and CHANGELOG.md, then qualify that exact commit with scripts/verify-release.mjs.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
