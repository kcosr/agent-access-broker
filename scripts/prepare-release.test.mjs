import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { prepareRelease } from "./prepare-release.mjs";
import { preparedRelease, UNRELEASED_TEMPLATE } from "./changelog.mjs";
import { workspaceVersion } from "./release-plan.mjs";

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "broker-release-prepare-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  git("init", "--initial-branch=feature");
  git("config", "user.name", "Release Test");
  git("config", "user.email", "release@example.test");
  const files = {
    "Cargo.toml": '[workspace]\nmembers = []\n\n[workspace.package]\nedition = "2024"\nversion = "0.1.0"\n\n[workspace.dependencies]\nother = "2.0"\n',
    "Cargo.lock": 'version = 4\n\n[[package]]\nname = "broker"\nversion = "0.1.0"\n\n[[package]]\nname = "cli"\nversion = "0.1.0"\n\n[[package]]\nname = "broker"\nversion = "9.0.0"\nsource = "registry+https://example.test/index"\nchecksum = "keep"\n',
    "CHANGELOG.md": "# Changelog\n\nSupported changes.\n\n## [Unreleased]\n\n### Breaking Changes\n\n### Added\n\n- Qualified releases.\n\n### Changed\n\n### Fixed\n\n### Removed\n",
  };
  for (const [file, content] of Object.entries(files)) writeFileSync(join(root, file), content);
  git("add", ".");
  git("commit", "--message", "Fixture");
  const head = git("rev-parse", "HEAD");
  const calls = [];
  const run = (command, args) => {
    calls.push([command, ...args]);
    if (command === "git") {
      assert.ok(["status", "rev-parse"].includes(args[0]), `Unexpected mutating Git command: ${args}`);
      return git(...args);
    }
    assert.equal(command, "cargo");
    assert.deepEqual(args, ["metadata", "--locked", "--no-deps", "--format-version", "1"]);
    const version = workspaceVersion(readFileSync(join(root, "Cargo.toml"), "utf8"));
    return JSON.stringify({ workspace_members: ["broker-id", "cli-id"], packages: [
      { id: "broker-id", name: "broker", version }, { id: "cli-id", name: "cli", version },
    ] });
  };
  return { root, files, head, git, calls, run };
}

test("preparation changes only release files, drops empty note headings, preserves dependency versions and leaves a reviewable uncommitted change", (t) => {
  const f = fixture(t);
  const result = prepareRelease("patch", { root: f.root, run: f.run, date: "2026-10-10" });
  assert.equal(result.version, "0.1.1");
  assert.equal(workspaceVersion(readFileSync(join(f.root, "Cargo.toml"), "utf8")), "0.1.1");
  const lock = readFileSync(join(f.root, "Cargo.lock"), "utf8");
  assert.equal((lock.match(/version = "0.1.1"/g) ?? []).length, 2);
  assert.match(lock, /name = "broker"\nversion = "9.0.0"\nsource/);
  const changelog = readFileSync(join(f.root, "CHANGELOG.md"), "utf8");
  assert.equal(changelog, `# Changelog\n\nSupported changes.\n\n${UNRELEASED_TEMPLATE}\n## [0.1.1] - 2026-10-10\n\n### Added\n\n- Qualified releases.\n`);
  assert.equal(preparedRelease(changelog, "0.1.1").notes, "### Added\n\n- Qualified releases.");
  assert.equal(f.git("rev-parse", "HEAD"), f.head);
  assert.equal(f.git("branch", "--show-current").trim(), "feature");
  assert.deepEqual(f.git("diff", "--name-only").trim().split("\n").sort(), Object.keys(f.files).sort());
  assert.equal(f.git("diff", "--cached", "--name-only"), "");
  assert.equal(f.calls.filter(([command]) => command === "cargo").length, 2);
});

test("preparation restores all three files byte-for-byte when final Cargo validation fails", (t) => {
  const f = fixture(t);
  let metadataCalls = 0;
  const run = (command, args) => {
    if (command === "cargo" && ++metadataCalls === 2) throw new Error("locked metadata rejected the update");
    return f.run(command, args);
  };
  assert.throws(() => prepareRelease("minor", { root: f.root, run }), /all three release files restored.*locked metadata rejected/);
  for (const [file, content] of Object.entries(f.files)) assert.equal(readFileSync(join(f.root, file), "utf8"), content);
  assert.equal(f.git("status", "--porcelain"), "");
  assert.equal(f.git("rev-parse", "HEAD"), f.head);
});

test("dirty, empty or already prepared candidates fail before writing or validating Cargo", (t) => {
  const f = fixture(t);
  writeFileSync(join(f.root, "untracked"), "preserve");
  assert.throws(() => prepareRelease("current", { root: f.root, run: f.run }), /clean worktree/);
  rmSync(join(f.root, "untracked"));
  writeFileSync(join(f.root, "CHANGELOG.md"), "# Changelog\n\n## [Unreleased]\n\n### Added\n\n## [0.1.0] - 2026-10-10\n\n### Added\n\n- Existing.\n");
  f.git("add", "CHANGELOG.md");
  f.git("commit", "--message", "Prepared baseline");
  assert.throws(() => prepareRelease("current", { root: f.root, run: f.run }), /already contains a \[0.1.0\]/);
  assert.throws(() => prepareRelease("patch", { root: f.root, run: f.run }), /no release notes/);
  assert.equal(f.calls.filter(([command]) => command === "cargo").length, 0);
  assert.equal(f.git("status", "--porcelain"), "");
});

test("malformed changelogs and edited released notes fail before writing or validating Cargo", (t) => {
  const f = fixture(t);
  const commit = (content, message) => {
    writeFileSync(join(f.root, "CHANGELOG.md"), content);
    f.git("add", "CHANGELOG.md");
    f.git("commit", "--message", message);
  };
  commit(f.files["CHANGELOG.md"].replace("### Changed", "### Maintenance"), "Unknown category");
  assert.throws(() => prepareRelease("minor", { root: f.root, run: f.run }), /Unknown changelog category in Unreleased: ### Maintenance/);
  const released = "## [0.1.0] - 2026-10-10\n\n### Added\n\n- Released.\n";
  commit(`${f.files["CHANGELOG.md"]}\n${released}`, "Released baseline");
  f.git("update-ref", "refs/remotes/origin/main", "HEAD");
  commit(`${f.files["CHANGELOG.md"]}\n${released.replace("Released.", "Rewritten.")}`, "Rewrite released notes");
  assert.throws(() => prepareRelease("minor", { root: f.root, run: f.run }), /Released changelog notes for 0.1.0 changed/);
  assert.equal(f.calls.filter(([command]) => command === "cargo").length, 0);
  assert.equal(f.git("status", "--porcelain"), "");
});

test("preparation rejects incoherent workspace versions before file mutations", (t) => {
  const f = fixture(t);
  const run = (command, args) => command === "cargo"
    ? JSON.stringify({ workspace_members: ["broker-id"], packages: [{ id: "broker-id", name: "broker", version: "8.0.0" }] })
    : f.run(command, args);
  assert.throws(() => prepareRelease("minor", { root: f.root, run }), /Every workspace package must use version 0.1.0/);
  assert.equal(f.git("status", "--porcelain"), "");
});

test("preparation rejects inherited Git overrides before commands and binds the actual repository root", (t) => {
  const actual = fixture(t);
  const decoy = fixture(t);
  const env = { ...process.env, GIT_DIR: join(decoy.root, ".git"), GIT_WORK_TREE: decoy.root, GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "test.secret", GIT_CONFIG_VALUE_0: "private-value" };
  assert.throws(() => prepareRelease("patch", { root: actual.root, env, run: actual.run }), (error) => {
    assert.match(error.message, /Unset Git repository\/index\/config overrides/);
    assert.ok(!error.message.includes("private-value"));
    assert.ok(!error.message.includes(decoy.root));
    return true;
  });
  assert.deepEqual(actual.calls, []);
  const nested = join(actual.root, "nested");
  mkdirSync(nested);
  assert.throws(() => prepareRelease("patch", { root: nested }), /source directory must be the Git repository root/);
  assert.equal(actual.git("status", "--porcelain"), "");
  assert.equal(decoy.git("status", "--porcelain"), "");
});
