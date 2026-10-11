import assert from "node:assert/strict";
import test from "node:test";
import { compareVersions, GITHUB_RELEASE_NOTES_LIMIT, nextCycleChangelog, parseVersion, prepareChangelog, preparedRelease, prepareVersionFiles, releaseRepository, releaseVersion, workspaceVersion } from "./release-plan.mjs";

test("GitHub release repository is bound to origin without copying URL credentials", () => {
  assert.equal(releaseRepository("git@github.com:example/broker.git"), "github.com/example/broker");
  assert.equal(releaseRepository("https://user:secret@github.com/example/broker.git"), "github.com/example/broker");
  assert.equal(releaseRepository("ssh://git@git.example.test:2222/example/broker.git"), "git.example.test/example/broker");
  for (const value of ["/tmp/mirror", "file:///tmp/mirror", "https://example.test/path/with/extra"]) assert.throws(() => releaseRepository(value), /origin must identify/);
});

test("release versions follow SemVer including prerelease and build metadata", () => {
  for (const value of ["1.0.0", "1.0.0-rc.1", "1.0.0-alpha-beta+build.001"]) assert.doesNotThrow(() => parseVersion(value));
  for (const value of ["01.0.0", "1.0.0-01", "1.0.0-alpha..1", "1.0.0-", "1.0.0_bad", "1.0", "-1.0.0"]) assert.throws(() => parseVersion(value), /Invalid semantic version/);
  assert.equal(compareVersions("1.0.0-rc.9", "1.0.0-rc.10"), -1);
  assert.equal(compareVersions("1.0.0", "1.0.0-rc.10"), 1);
  assert.equal(compareVersions("1.0.0+build.1", "1.0.0+build.2"), 0);
});

test("version selection rejects equal or older explicit versions before edits", () => {
  assert.equal(releaseVersion("0.1.0", "current"), "0.1.0");
  assert.equal(releaseVersion("0.1.0-rc.1", "patch"), "0.1.1");
  assert.equal(releaseVersion("0.1.9", "minor"), "0.2.0");
  assert.equal(releaseVersion("0.1.9", "major"), "1.0.0");
  assert.equal(releaseVersion("1.0.0-rc.1", "1.0.0"), "1.0.0");
  assert.equal(releaseVersion("1.0.9007199254740992", "patch"), "1.0.9007199254740993");
  for (const next of ["0.1.0", "0.0.9", "0.1.0+build", "0.1.0-rc.1"]) assert.throws(() => releaseVersion("0.1.0", next), /must be newer/);
});

test("changelog preflight refuses malformed, empty, duplicate and already released notes", () => {
  for (const content of ["## [Unreleased]\n- Note", "# Changelog\n\n## [Unreleased]\n\n_No unreleased changes._", "# Changelog\n\n## [Unreleased]\n- Note\n## [Unreleased]\n- Note", "# Changelog\n\n## [Unreleased]\n- Note\n## [1.0.0]\n- Older"]) {
    assert.throws(() => prepareChangelog(content, "1.0.0", "2026-09-30"));
  }
  const original = "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- Avoid failed releases.\n\n## [0.9.0] - 2026-01-01\n\n- Original.\n";
  const prepared = prepareChangelog(original, "1.0.0-rc.1+build", "2026-09-30");
  assert.equal(prepared.notes, "### Fixed\n\n- Avoid failed releases.");
  assert.ok(prepared.content.includes("## [1.0.0-rc.1+build] - 2026-09-30"));
  assert.ok(nextCycleChangelog(prepared.content).includes("## [Unreleased]\n\n### Breaking Changes"));
  assert.throws(() => nextCycleChangelog(original));
});

test("release-note size is checked at preflight including the exact Unicode character boundary", () => {
  const notes = `- ${"🛠".repeat(GITHUB_RELEASE_NOTES_LIMIT - 2)}`;
  const changelog = (body) => `# Changelog\n\n## [Unreleased]\n\n${body}\n\n## [0.9.0] - 2026-01-01\n\n- ${"x".repeat(GITHUB_RELEASE_NOTES_LIMIT)}\n`;
  assert.equal(prepareChangelog(changelog(notes), "1.0.0", "2026-10-10").notes, notes);
  const oversized = changelog(`${notes}x`);
  assert.throws(() => prepareChangelog(oversized, "1.0.0", "2026-10-10"),
    /Release notes contain 125001 characters; GitHub permits at most 125000/);
  assert.ok(oversized.includes("## [Unreleased]"));
  assert.ok(!oversized.includes("## [1.0.0]"));
});

test("new release cycles preserve the introduction above all release notes", () => {
  const introduction = "# Changelog\n\nSupported product changes are listed below.\nSee the documentation for current behavior.\n\n";
  const initial = `${introduction}## [Unreleased]\n\n### Added\n\n- First release.\n`;
  const released = prepareChangelog(initial, "1.0.0", "2026-10-10");
  assert.equal(released.notes, "### Added\n\n- First release.");
  const nextCycle = nextCycleChangelog(released.content);
  assert.ok(nextCycle.startsWith(`${introduction}## [Unreleased]\n`));
  assert.equal(nextCycle.split(introduction).length, 2);
  assert.ok(nextCycle.endsWith("## [1.0.0] - 2026-10-10\n\n### Added\n\n- First release.\n"));
  assert.throws(() => prepareChangelog(nextCycle, "1.0.1", "2026-10-11"), /no release notes/);
  const second = prepareChangelog(nextCycle.replace("### Fixed\n", "### Fixed\n\n- Second release.\n"), "1.0.1", "2026-10-11");
  assert.ok(!second.notes.includes("Supported product changes"));
  assert.ok(!second.notes.includes("First release"));
  assert.ok(second.notes.includes("Second release"));
  assert.ok(nextCycleChangelog(second.content).startsWith(`${introduction}## [Unreleased]\n`));
  assert.throws(() => nextCycleChangelog(introduction), /must contain a release section/);
});

test("prepared candidates require empty Unreleased, the current dated release and bounded notes", () => {
  const valid = "# Changelog\n\nIntroduction.\n\n## [Unreleased]\n\n### Added\n\n## [0.1.0] - 2026-10-10\n\n- Initial release.\n";
  assert.deepEqual(preparedRelease(valid, "0.1.0"), { version: "0.1.0", tag: "v0.1.0", date: "2026-10-10", notes: "- Initial release." });
  for (const invalid of [
    valid.replace("### Added", "- Unreviewed change."),
    valid.replace("## [0.1.0]", "## [0.2.0]"),
    valid.replace("2026-10-10", "2026-02-30"),
    valid.replace("- Initial release.", "### Added"),
    `${valid}\n## [0.1.0] - 2026-10-10\n\n- Duplicate.\n`,
    `${valid}\n## [Unreleased]\n`,
    valid.replace("- Initial release.", `- ${"x".repeat(GITHUB_RELEASE_NOTES_LIMIT)}`),
  ]) assert.throws(() => preparedRelease(invalid, "0.1.0"));
  const exact = valid.replace("- Initial release.", `- ${"x".repeat(GITHUB_RELEASE_NOTES_LIMIT - 2)}`);
  assert.equal(preparedRelease(exact, "0.1.0").notes.length, GITHUB_RELEASE_NOTES_LIMIT);
});

test("release file parsing supports native Windows line endings and keeps workspace and registry entries distinct", () => {
  const manifest = '[workspace.package]\r\nversion = "0.1.0"\r\n\r\n[workspace.dependencies]\r\nversioned = "8"\r\n';
  const lock = 'version = 4\r\n\r\n[[package]]\r\nname = "broker"\r\nversion = "0.1.0"\r\n';
  const changelog = '# Changelog\r\n\r\n## [Unreleased]\r\n\r\n- Initial release.\r\n';
  assert.equal(workspaceVersion(manifest), "0.1.0");
  const files = prepareVersionFiles(manifest, lock, ["broker"], "0.2.0");
  assert.equal(workspaceVersion(files.manifest), "0.2.0");
  assert.match(files.manifest, /versioned = "8"/);
  assert.match(files.lock, /version = "0.2.0"/);
  assert.equal(preparedRelease(nextCycleChangelog(prepareChangelog(changelog, "0.2.0", "2026-10-10").content), "0.2.0").notes, "- Initial release.");
  assert.throws(() => prepareVersionFiles(manifest, lock, ["missing"], "0.2.0"), /entry not found/);
  assert.throws(() => prepareVersionFiles(manifest, lock.replace('version = "0.1.0"', 'version = "9.0.0"'), ["broker"], "0.2.0"), /version differs/);
});
