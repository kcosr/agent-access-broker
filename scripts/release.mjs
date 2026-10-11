#!/usr/bin/env node
/** Publish only an already prepared, qualified commit. Never edit or commit source. */
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseVersion, preparedRelease, releaseRepository, workspaceVersion } from "./release-plan.mjs";
import { validateQualification } from "./release-qualification.mjs";
import { assertNoGitOverrides } from "./release-environment.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const USAGE = "Usage: node scripts/release.mjs --qualification FILE";

export function parsePublishArguments(args) {
  if (args.length !== 2 || args[0] !== "--qualification" || !args[1] || args[1].startsWith("--")) throw new Error(USAGE);
  return { qualificationPath: args[1] };
}

function cleanMain(run, root, expected) {
  if (realpathSync(run("git", ["rev-parse", "--show-toplevel"]).trim()) !== realpathSync(root)) {
    throw new Error("Publication source directory must be the Git repository root");
  }
  if (run("git", ["branch", "--show-current"]).trim() !== "main") throw new Error("Publication requires the main branch");
  if (run("git", ["status", "--porcelain"]).trim()) throw new Error("Publication requires a clean worktree");
  const commit = run("git", ["rev-parse", "HEAD"]).trim();
  if (expected && commit !== expected) throw new Error("Checkout changed during publication preflight");
  return commit;
}

function releaseQuery(run, repository, tag) {
  // Listing succeeds with an empty array when absent. API/auth failures must not
  // be mistaken for an absent release and followed by a create attempt.
  const pages = JSON.parse(run("gh", ["api", "--hostname", repository.split("/")[0], "--paginate", "--slurp",
    `repos/${repository.split("/").slice(1).join("/")}/releases?per_page=100`]));
  if (!Array.isArray(pages) || pages.some((page) => !Array.isArray(page))) throw new Error("Unexpected GitHub release list response");
  const matches = pages.flat().filter((entry) => entry.tag_name === tag);
  if (matches.length > 1) throw new Error(`GitHub has multiple releases for ${tag}`);
  return matches[0];
}

function matchingDraft(draft, release, commit, prerelease) {
  if (!draft.draft) throw new Error(`GitHub release ${release.tag} is already published; existing releases are never overwritten`);
  if (draft.tag_name !== release.tag || draft.target_commitish !== commit
      || draft.name !== release.tag || draft.body !== release.notes || draft.prerelease !== prerelease) {
    throw new Error(`Existing draft ${release.tag} does not match the qualified commit and prepared release notes`);
  }
}

export function publishRelease({
  qualificationPath,
  root = ROOT,
  env = process.env,
  run = (command, args) => execFileSync(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }),
}) {
  if (!qualificationPath) throw new Error(USAGE);
  assertNoGitOverrides(env);
  const commit = cleanMain(run, root);
  const version = workspaceVersion(readFileSync(join(root, "Cargo.toml"), "utf8"));
  const release = preparedRelease(readFileSync(join(root, "CHANGELOG.md"), "utf8"), version);
  validateQualification(JSON.parse(readFileSync(resolve(root, qualificationPath), "utf8")), { commit, version });
  const repository = releaseRepository(run("git", ["remote", "get-url", "origin"]).trim());
  run("gh", ["--version"]);
  run("gh", ["auth", "status", "--hostname", repository.split("/")[0]]);
  run("gh", ["repo", "view", repository, "--json", "nameWithOwner"]);
  run("git", ["fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main"]);
  if (run("git", ["rev-parse", "refs/remotes/origin/main"]).trim() !== commit) {
    throw new Error("Publication requires qualified main to match freshly fetched origin/main");
  }
  const tagRef = `refs/tags/${release.tag}`;
  const localObject = run("git", ["for-each-ref", "--format=%(objectname)", tagRef]).trim();
  if (localObject) {
    if (run("git", ["cat-file", "-t", tagRef]).trim() !== "tag"
        || run("git", ["rev-parse", `${tagRef}^{commit}`]).trim() !== commit) {
      throw new Error(`Existing local tag ${release.tag} must be annotated and point to the qualified commit`);
    }
  }
  const remote = new Map(run("git", ["ls-remote", "--tags", "origin", tagRef, `${tagRef}^{}`]).trim().split("\n")
    .filter(Boolean).map((line) => { const [object, ref] = line.split(/\s+/); return [ref, object]; }));
  const remoteObject = remote.get(tagRef);
  if ((remoteObject && remote.get(`${tagRef}^{}`) !== commit)
      || (!remoteObject && remote.size) || (remoteObject && localObject && localObject !== remoteObject)) {
    throw new Error(`Existing remote tag ${release.tag} must be the matching annotated tag at the qualified commit`);
  }
  const prerelease = parseVersion(version).prerelease.length > 0;
  let draft = releaseQuery(run, repository, release.tag);
  if (draft) matchingDraft(draft, release, commit, prerelease);
  cleanMain(run, root, commit);

  try {
    if (!remoteObject) {
      if (!localObject) run("git", ["tag", "--annotate", release.tag, commit, "--message", `Release ${release.tag}`]);
      run("git", ["push", "origin", `${tagRef}:${tagRef}`]);
    }
    if (!draft) {
      const directory = mkdtempSync(join(tmpdir(), "agent-access-release-notes-"));
      try {
        const notesFile = join(directory, "notes.md");
        writeFileSync(notesFile, release.notes, { mode: 0o600 });
        run("gh", ["release", "create", release.tag, "--repo", repository, "--draft", "--verify-tag", "--target", commit,
          "--title", release.tag, "--notes-file", notesFile, ...(prerelease ? ["--prerelease"] : [])]);
      } finally { rmSync(directory, { recursive: true, force: true }); }
      draft = releaseQuery(run, repository, release.tag);
      if (!draft) throw new Error("GitHub draft was not found after creation");
      matchingDraft(draft, release, commit, prerelease);
    }
    // This is the final write. A tag or matching draft can remain on failure;
    // rerunning checks every precondition before safely continuing that state.
    run("gh", ["release", "edit", release.tag, "--repo", repository, "--draft=false"]);
  } catch (error) {
    throw new Error(`Publication of ${release.tag} failed. A matching tag or draft may remain; rerun with the same qualification after correcting the failure. No tags were moved or deleted. ${error.message}`);
  }
  return { ...release, commit, repository };
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    const result = publishRelease(parsePublishArguments(process.argv.slice(2)));
    console.log(`Published ${result.tag} from qualified commit ${result.commit}.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
