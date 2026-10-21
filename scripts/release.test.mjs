import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { parsePublishArguments, publishRelease } from "./release.mjs";
import { REQUIRED_RELEASE_CHECKS } from "./release-qualification.mjs";

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "broker-release-publish-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  git("init", "--initial-branch=main");
  git("config", "user.name", "Release Test");
  git("config", "user.email", "release@example.test");
  git("remote", "add", "origin", "https://github.com/example/broker.git");
  writeFileSync(join(root, "Cargo.toml"), '[workspace.package]\nversion = "0.1.0"\n');
  writeFileSync(join(root, "Cargo.lock"), 'version = 4\n');
  writeFileSync(join(root, "CHANGELOG.md"), "# Changelog\n\n## [Unreleased]\n\n### Added\n\n## [0.1.0] - 2026-10-10\n\n### Added\n\n- Qualified release.\n\n### Removed\n");
  git("add", ".");
  git("commit", "--message", "Prepared release");
  const commit = git("rev-parse", "HEAD").trim();
  // Receipts live outside tracked source (here in the isolated Git metadata).
  const qualificationPath = join(root, ".git", "qualification.json");
  const report = {
    schemaVersion: 1, status: "passed", sourceClean: true, commit, version: "0.1.0", platform: "linux", target: "x86_64-unknown-linux-gnu",
    startedAt: "2026-10-10T00:00:00Z", finishedAt: "2026-10-10T01:00:00Z",
    checks: REQUIRED_RELEASE_CHECKS.map((id) => ({ id, status: "passed", exitCode: 0, command: ["fixture", id] })),
  };
  writeFileSync(qualificationPath, JSON.stringify(report));
  const calls = [];
  const state = { remoteMain: commit, remoteObject: undefined, remoteCommit: undefined, draft: undefined, notesFile: undefined, fail: undefined };
  const run = (command, args) => {
    calls.push([command, ...args]);
    if (state.fail?.(command, args)) throw new Error("injected command failure");
    if (command === "git") {
      if (args[0] === "fetch") {
        assert.deepEqual(args, ["fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main"]);
        return git("update-ref", "refs/remotes/origin/main", state.remoteMain);
      }
      if (args[0] === "ls-remote") return state.remoteObject ? `${state.remoteObject}\trefs/tags/v0.1.0\n${state.remoteCommit}\trefs/tags/v0.1.0^{}\n` : "";
      if (args[0] === "push") {
        assert.deepEqual(args, ["push", "origin", "refs/tags/v0.1.0:refs/tags/v0.1.0"]);
        state.remoteObject = git("rev-parse", "refs/tags/v0.1.0").trim();
        state.remoteCommit = git("rev-parse", "refs/tags/v0.1.0^{commit}").trim();
        return "";
      }
      assert.ok(["branch", "status", "rev-parse", "remote", "for-each-ref", "cat-file", "tag"].includes(args[0]), `Unexpected Git command: ${args}`);
      return git(...args);
    }
    assert.equal(command, "gh");
    if (args[0] === "api") return JSON.stringify([[...(state.draft ? [state.draft] : [])]]);
    if (args[0] === "repo") {
      assert.deepEqual(args, ["repo", "view", "github.com/example/broker", "--json", "nameWithOwner"]);
      return "";
    }
    if (["--version", "auth"].includes(args[0])) return "";
    assert.equal(args[0], "release");
    assert.equal(args[args.indexOf("--repo") + 1], "github.com/example/broker");
    if (args[1] === "create") {
      assert.ok(args.includes("--draft"));
      assert.ok(args.includes("--verify-tag"));
      state.notesFile = args[args.indexOf("--notes-file") + 1];
      state.draft = { tag_name: "v0.1.0", target_commitish: args[args.indexOf("--target") + 1], name: "v0.1.0", body: readFileSync(state.notesFile, "utf8"), draft: true, prerelease: false };
      return "";
    }
    assert.deepEqual(args, ["release", "edit", "v0.1.0", "--repo", "github.com/example/broker", "--draft=false"]);
    assert.equal(state.remoteCommit, commit);
    state.draft.draft = false;
    return "";
  };
  const publish = () => publishRelease({ root, qualificationPath, run });
  return { root, git, report, qualificationPath, commit, calls, state, run, publish };
}

const writes = (calls) => calls.filter(([command, operation, ...args]) =>
  (command === "git" && (operation === "push" || operation === "tag")) || (command === "gh" && operation === "release" && ["create", "edit"].includes(args[0])));

test("publication accepts only a qualification file argument", () => {
  assert.deepEqual(parsePublishArguments(["--qualification", "receipt.json"]), { qualificationPath: "receipt.json" });
  for (const args of [[], ["patch"], ["current"], ["--qualification"], ["--qualification", "--bad"], ["--qualification", "receipt", "extra"]]) assert.throws(() => parsePublishArguments(args), /Usage/);
});

test("publication tags the exact qualified commit, pushes only that tag and publishes a verified draft last", (t) => {
  const f = fixture(t);
  const result = f.publish();
  assert.equal(result.commit, f.commit);
  assert.equal(f.git("cat-file", "-t", "refs/tags/v0.1.0").trim(), "tag");
  assert.equal(f.git("rev-parse", "refs/tags/v0.1.0^{commit}").trim(), f.commit);
  assert.equal(f.git("rev-parse", "HEAD").trim(), f.commit);
  assert.equal(f.git("status", "--porcelain"), "");
  assert.deepEqual(writes(f.calls).map(([command, operation, next]) => `${command} ${operation}${command === "gh" ? ` ${next}` : ""}`), ["git tag", "git push", "gh release create", "gh release edit"]);
  assert.deepEqual(f.calls.at(-1), ["gh", "release", "edit", "v0.1.0", "--repo", "github.com/example/broker", "--draft=false"]);
  assert.equal(f.state.draft.body, "### Added\n\n- Qualified release.", "empty note headings are not published");
  assert.equal(f.state.draft.draft, false);
  assert.equal(existsSync(f.state.notesFile), false);
});

test("missing, stale, failed and incomplete qualifications fail before any tag or network writes", (t) => {
  const f = fixture(t);
  for (const report of [{ ...f.report, commit: "f".repeat(40) }, { ...f.report, status: "failed" }, { ...f.report, checks: [] }, { ...f.report, version: "0.2.0" }]) {
    writeFileSync(f.qualificationPath, JSON.stringify(report));
    assert.throws(f.publish, /Qualification/);
  }
  rmSync(f.qualificationPath);
  assert.throws(f.publish, /ENOENT/);
  assert.deepEqual(writes(f.calls), []);
  assert.ok(!f.calls.some(([command, operation]) => command === "gh" || operation === "fetch"));
});

test("remote divergence, dirty source and unprepared changelog fail before publication writes", (t) => {
  const f = fixture(t);
  f.git("commit", "--allow-empty", "--message", "Newer remote");
  f.state.remoteMain = f.git("rev-parse", "HEAD").trim();
  f.git("reset", "--hard", f.commit);
  assert.throws(f.publish, /freshly fetched origin\/main/);
  f.state.remoteMain = f.commit;
  writeFileSync(join(f.root, "untracked"), "preserve");
  assert.throws(f.publish, /clean worktree/);
  rmSync(join(f.root, "untracked"));
  writeFileSync(join(f.root, "CHANGELOG.md"), "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- New work.\n");
  f.git("add", "CHANGELOG.md");
  f.git("commit", "--message", "Unprepared candidate");
  assert.throws(f.publish, /Prepared changelog/);
  assert.deepEqual(writes(f.calls), []);
});

test("existing published releases and mismatched drafts are never changed", (t) => {
  const f = fixture(t);
  f.state.draft = { tag_name: "v0.1.0", target_commitish: f.commit, name: "v0.1.0", body: "### Added\n\n- Qualified release.", draft: false, prerelease: false };
  assert.throws(f.publish, /already published/);
  f.state.draft.draft = true;
  f.state.draft.body = "Unexpected content";
  assert.throws(f.publish, /does not match/);
  assert.deepEqual(writes(f.calls), []);
});

test("a failed final publish retains the exact tag and matching draft and safely resumes", (t) => {
  const f = fixture(t);
  f.state.fail = (command, args) => command === "gh" && args[0] === "release" && args[1] === "edit";
  assert.throws(f.publish, /matching tag or draft may remain/);
  assert.equal(f.state.remoteCommit, f.commit);
  assert.equal(f.state.draft.draft, true);
  const object = f.state.remoteObject;
  assert.equal(existsSync(f.state.notesFile), false);
  f.state.fail = undefined;
  f.calls.length = 0;
  f.publish();
  assert.equal(f.state.remoteObject, object);
  assert.deepEqual(writes(f.calls), [["gh", "release", "edit", "v0.1.0", "--repo", "github.com/example/broker", "--draft=false"]]);
  f.calls.length = 0;
  assert.throws(f.publish, /already published/);
  assert.deepEqual(writes(f.calls), []);
});

test("wrong or lightweight existing tags are rejected without moving or deleting them", (t) => {
  const f = fixture(t);
  f.git("tag", "v0.1.0");
  assert.throws(f.publish, /must be annotated/);
  f.git("tag", "--delete", "v0.1.0");
  f.git("commit", "--allow-empty", "--message", "Different revision");
  f.git("tag", "--annotate", "v0.1.0", "--message", "Wrong release");
  const wrongTag = f.git("rev-parse", "refs/tags/v0.1.0").trim();
  f.git("reset", "--hard", f.commit);
  assert.throws(f.publish, /point to the qualified commit/);
  assert.equal(f.git("rev-parse", "refs/tags/v0.1.0").trim(), wrongTag);
  assert.deepEqual(writes(f.calls), []);
  f.git("tag", "--delete", "v0.1.0");
  f.state.remoteObject = "a".repeat(40);
  f.state.remoteCommit = "b".repeat(40);
  assert.throws(f.publish, /Existing remote tag/);
  assert.deepEqual(writes(f.calls), []);
});

test("GitHub read failures are not treated as an absent release", (t) => {
  const f = fixture(t);
  f.state.fail = (command, args) => command === "gh" && args[0] === "api";
  assert.throws(f.publish, /injected command failure/);
  assert.deepEqual(writes(f.calls), []);
});

test("publication rejects inherited Git overrides before commands and binds the actual repository root", (t) => {
  const actual = fixture(t);
  const decoy = fixture(t);
  const env = { ...process.env, GIT_DIR: join(decoy.root, ".git"), GIT_WORK_TREE: decoy.root, GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "test.secret", GIT_CONFIG_VALUE_0: "private-value" };
  assert.throws(() => publishRelease({ root: actual.root, qualificationPath: actual.qualificationPath, env, run: actual.run }), (error) => {
    assert.match(error.message, /Unset Git repository\/index\/config overrides/);
    assert.ok(!error.message.includes("private-value"));
    assert.ok(!error.message.includes(decoy.root));
    return true;
  });
  assert.deepEqual(actual.calls, []);
  const nested = join(actual.root, "nested");
  mkdirSync(nested);
  assert.throws(() => publishRelease({ root: nested, qualificationPath: actual.qualificationPath }), /source directory must be the Git repository root/);
  assert.equal(actual.git("status", "--porcelain"), "");
  assert.equal(decoy.git("status", "--porcelain"), "");
});
