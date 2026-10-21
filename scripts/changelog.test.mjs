import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { assertReleasedNotesUnchanged, checkChangelog, cleanNotes, GITHUB_RELEASE_NOTES_LIMIT, parseChangelog,
  prepareChangelog, preparedRelease, UNRELEASED_TEMPLATE } from "./changelog.mjs";

const introduction = "# Changelog\n\nSupported product changes are listed below.\n\n";
const initial = "## [0.1.0] - 2026-10-11\n\n### Initial release\n\n- A standalone Broker.\n  Wrapped continuation.\n";
const changelog = (notes = "### Added\n\n- A feature.", history = initial) => `${introduction}## [Unreleased]\n\n${notes}\n\n${history}`;

function temporaryRoot(t) {
  const root = mkdtempSync(join(tmpdir(), "broker-changelog-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test("accepts the introduction, wrapped notes, empty Unreleased template headings and native line endings", () => {
  const text = changelog("### Breaking Changes\n\n- Upgrade clients.\n  See the upgrade notes.\n\n  ```toml\n  [limits]\n  ```\n\n### Fixed");
  assert.deepEqual(parseChangelog(text).map((entry) => entry.name), ["Unreleased", "0.1.0"]);
  assert.equal(parseChangelog(text)[1].date, "2026-10-11");
  assert.equal(parseChangelog(`${introduction}${UNRELEASED_TEMPLATE}\n${initial}`).length, 2);
  assert.equal(parseChangelog(changelog("")).length, 2);
  assert.equal(parseChangelog(text.replace(/\n/g, "\r\n")).length, 2);
  assert.equal(cleanNotes(parseChangelog(text)[0].body), "### Breaking Changes\n\n- Upgrade clients.\n  See the upgrade notes.\n\n  ```toml\n  [limits]\n  ```");
});

test("the Initial release heading is accepted only in the frozen 0.1.0 section", () => {
  assert.equal(parseChangelog(changelog()).length, 2);
  assert.throws(() => parseChangelog(changelog("### Initial release\n\n- New.")), /Unknown changelog category in Unreleased: ### Initial release/);
  const later = `## [0.2.0] - 2026-11-01\n\n### Initial release\n\n- Later.\n\n${initial}`;
  assert.throws(() => parseChangelog(changelog("", later)), /Unknown changelog category in 0.2.0: ### Initial release/);
  assert.equal(parseChangelog(changelog("", later.replace("### Initial release", "### Added"))).length, 3);
});

test("rejects malformed structure, categories, notes, headings, dates and ordering", () => {
  const cases = [
    ["missing title", changelog().replace("# Changelog\n", "# Releases\n"), /must start with '# Changelog'/],
    ["release before Unreleased", `${introduction}${initial}\n## [Unreleased]\n`, /first CHANGELOG.md section must be ## \[Unreleased\]/],
    ["no sections", introduction, /first CHANGELOG.md section/],
    ["duplicate Unreleased", changelog("### Added\n\n## [Unreleased]"), /Duplicate changelog section: Unreleased/],
    ["duplicate release", changelog("", `${initial}\n${initial}`), /Duplicate changelog section: 0.1.0/],
    ["duplicate category", changelog("### Added\n\n- One.\n\n### Added\n\n- Two."), /Duplicate changelog category in Unreleased: Added/],
    ["unknown category", changelog("### Maintenance\n\n- One."), /Unknown changelog category/],
    ["subheading", changelog("### Added\n\n#### Portal\n\n- One."), /Unknown changelog category/],
    ["missing category", changelog("- One."), /must be bullets/],
    ["uncategorized release", changelog("", "## [0.1.0] - 2026-10-11\n\n- One.\n"), /0.1.0 notes must be bullets/],
    ["prose", changelog("### Fixed\n\nA fix."), /must be bullets/],
    ["other bullet marker", changelog("### Fixed\n\n* A fix."), /must be bullets/],
    ["unindented continuation", changelog("### Fixed\n\n- A fix.\ncontinued"), /must be bullets/],
    ["empty bullet", changelog("### Fixed\n\n- "), /Empty changelog note in Unreleased/],
    ["empty nested bullet", changelog("### Fixed\n\n- A fix.\n  -"), /Empty changelog note/],
    ["empty released bullet", changelog("", "## [0.1.0] - 2026-10-11\n\n### Added\n\n-\n"), /Empty changelog note in 0.1.0/],
    ["missing date", changelog("", "## [0.1.0]\n\n### Added\n\n- One.\n"), /Malformed changelog release heading/],
    ["invalid date", changelog("", "## [0.1.0] - 2026-02-30\n\n### Added\n\n- One.\n"), /Invalid changelog release date/],
    ["invalid version", changelog("", "## [01.1.0] - 2026-10-11\n\n### Added\n\n- One.\n"), /Malformed changelog release heading/],
    ["missing heading space", changelog("", "##[0.1.0] - 2026-10-11\n\n### Added\n\n- One.\n"), /Malformed changelog release heading/],
    ["empty release", changelog("", "## [0.1.0] - 2026-10-11\n\n### Added\n"), /No release notes for 0.1.0/],
    ["ascending versions", changelog("", `${initial}\n## [0.2.0] - 2026-11-01\n\n### Added\n\n- Later.\n`), /descending version order/],
    ["equal precedence", changelog("", `## [1.0.0+b] - 2026-11-02\n\n### Added\n\n- B.\n\n## [1.0.0+a] - 2026-11-01\n\n### Added\n\n- A.\n`), /descending version order/],
  ];
  for (const [name, text, message] of cases) assert.throws(() => parseChangelog(text), message, name);
  assert.equal(parseChangelog(changelog("", `## [1.0.0] - 2026-11-02\n\n### Added\n\n- Final.\n\n## [1.0.0-rc.1] - 2026-11-01\n\n### Added\n\n- Candidate.\n\n${initial}`)).length, 4);
});

test("released notes stay byte-identical while new releases and Unreleased edits are allowed", () => {
  const baseline = changelog();
  const current = changelog("### Fixed\n\n- A fix.", `## [0.2.0] - 2026-11-01\n\n### Added\n\n- A feature.\n\n${initial}`);
  assert.doesNotThrow(() => assertReleasedNotesUnchanged(parseChangelog(current), baseline));
  assert.doesNotThrow(() => assertReleasedNotesUnchanged(parseChangelog(current), baseline.replace("### Added", "Malformed baseline prose")));
  assert.doesNotThrow(() => assertReleasedNotesUnchanged(parseChangelog(current), baseline.replace(/\n/g, "\r\n")));
  for (const changed of [
    current.replace("A standalone Broker", "An edited Broker"),
    current.replace(initial, "## [0.0.9] - 2026-10-01\n\n### Added\n\n- Replacement.\n"),
    current.replace("2026-10-11", "2026-10-12"),
    `${current.trimEnd()}\n\n`,
  ]) assert.throws(() => assertReleasedNotesUnchanged(parseChangelog(changed), baseline), /Released changelog notes for 0.1.0 changed/);
});

test("committed edits are checked against the local origin/main merge-base without contacting a remote", (t) => {
  const root = temporaryRoot(t);
  const env = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" };
  for (const name of Object.keys(env)) if (/^GIT_(DIR|WORK_TREE|INDEX_FILE|COMMON_DIR|OBJECT_DIRECTORY|CONFIG_(COUNT|PARAMETERS|KEY_|VALUE_))/.test(name)) delete env[name];
  const git = (...args) => execFileSync("git", args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  git("init", "--initial-branch=main");
  git("config", "user.name", "Changelog Test");
  git("config", "user.email", "changelog@example.test");
  git("config", "commit.gpgsign", "false");
  const commit = (text, message) => { writeFileSync(join(root, "CHANGELOG.md"), text); git("add", "CHANGELOG.md"); git("commit", "--message", message); };
  commit(changelog(), "Baseline");
  const baseline = git("rev-parse", "HEAD");
  assert.equal(checkChangelog(root, { env }).baseline, baseline, "HEAD is the baseline without origin/main");
  writeFileSync(join(root, "CHANGELOG.md"), changelog().replace("A standalone", "An uncommitted"));
  assert.throws(() => checkChangelog(root, { env }), /Released changelog notes for 0.1.0 changed/);
  git("update-ref", "refs/remotes/origin/main", baseline);
  git("switch", "--create", "feature");
  commit(changelog("### Fixed\n\n- A fix."), "Unreleased edit");
  assert.equal(checkChangelog(root, { env }).baseline, baseline);
  commit(changelog().replace("A standalone", "A committed"), "Rewrite history");
  assert.throws(() => checkChangelog(root, { env }), /Released changelog notes for 0.1.0 changed/);
});

test("source exports validate structure without Git history", (t) => {
  const root = temporaryRoot(t);
  writeFileSync(join(root, "CHANGELOG.md"), changelog());
  assert.equal(checkChangelog(root).baseline, null);
  writeFileSync(join(root, "CHANGELOG.md"), changelog("### Fixed\n\n- "));
  assert.throws(() => checkChangelog(root), /Empty changelog note/);
});

test("preparation stamps notes without empty category headings and opens a fresh Unreleased template", () => {
  const notes = "### Added\n\n- New action.\n\n### Fixed\n\n- A fix.\n  Continued.";
  const unreleased = UNRELEASED_TEMPLATE.replace("### Added\n", "### Added\n\n- New action.\n").replace("### Fixed\n", "### Fixed\n\n- A fix.\n  Continued.\n");
  const prepared = prepareChangelog(`${introduction}${unreleased}\n${initial}`, "0.2.0", "2026-10-21");
  assert.equal(prepared.notes, notes);
  assert.equal(prepared.content, `${introduction}${UNRELEASED_TEMPLATE}\n## [0.2.0] - 2026-10-21\n\n${notes}\n\n${initial}`);
  assert.equal(preparedRelease(prepared.content, "0.2.0").notes, notes);
  const emptyRemoved = prepareChangelog(changelog("### Added\n\n- Only addition.\n\n### Removed"), "0.2.0", "2026-10-21");
  assert.equal(emptyRemoved.notes, "### Added\n\n- Only addition.");
  assert.ok(emptyRemoved.content.includes("## [0.2.0] - 2026-10-21\n\n### Added\n\n- Only addition.\n\n## [0.1.0] - 2026-10-11\n"));
  const windows = prepareChangelog("# Changelog\r\n\r\n## [Unreleased]\r\n\r\n### Added\r\n\r\n- First release.\r\n", "0.2.0", "2026-10-10");
  assert.equal(preparedRelease(windows.content, "0.2.0").notes, "### Added\n\n- First release.");
});

test("preparation refuses malformed, empty, duplicate, older and already released notes", () => {
  for (const [text, message] of [
    ["## [Unreleased]\n\n### Added\n\n- Note.\n", /must start with '# Changelog'/],
    [changelog(""), /no release notes under \[Unreleased\]/],
    [changelog(UNRELEASED_TEMPLATE.slice("## [Unreleased]\n\n".length)), /no release notes/],
    [changelog("_No unreleased changes._"), /must be bullets/],
    [changelog("- Uncategorized."), /must be bullets/],
    [changelog("### Added\n\n- Note.", `## [1.0.0] - 2026-09-01\n\n### Added\n\n- Released.\n\n${initial}`), /already contains a \[1.0.0\] section/],
    [changelog("### Added\n\n- Note.", `## [1.1.0] - 2026-09-01\n\n### Added\n\n- Newer.\n\n${initial}`), /must be newer than changelog release 1.1.0/],
  ]) assert.throws(() => prepareChangelog(text, "1.0.0", "2026-09-30"), message);
  assert.throws(() => prepareChangelog(changelog(), "1.0.0", "2026-02-30"), /Invalid changelog release date/);
  const prepared = prepareChangelog(changelog("### Fixed\n\n- Avoid failed releases."), "1.0.0-rc.1+build", "2026-09-30");
  assert.equal(prepared.notes, "### Fixed\n\n- Avoid failed releases.");
  assert.ok(prepared.content.includes(`${UNRELEASED_TEMPLATE}\n## [1.0.0-rc.1+build] - 2026-09-30\n`));
});

test("release-note size is checked at preflight including the exact Unicode character boundary", () => {
  const notes = `### Added\n\n- ${"🛠".repeat(GITHUB_RELEASE_NOTES_LIMIT - 13)}`;
  const text = (body) => changelog(body, `## [0.9.0] - 2026-01-01\n\n### Added\n\n- ${"x".repeat(GITHUB_RELEASE_NOTES_LIMIT)}\n`);
  assert.equal(prepareChangelog(text(notes), "1.0.0", "2026-10-10").notes, notes);
  assert.throws(() => prepareChangelog(text(`${notes}x`), "1.0.0", "2026-10-10"),
    /Release notes contain 125001 characters; GitHub permits at most 125000/);
});

test("new release cycles preserve the introduction above all release notes", () => {
  const released = prepareChangelog(`${introduction}## [Unreleased]\n\n### Added\n\n- First release.\n`, "1.0.0", "2026-10-10");
  assert.equal(released.notes, "### Added\n\n- First release.");
  assert.ok(released.content.startsWith(`${introduction}## [Unreleased]\n`));
  assert.equal(released.content.split(introduction).length, 2);
  assert.ok(released.content.endsWith("## [1.0.0] - 2026-10-10\n\n### Added\n\n- First release.\n"));
  assert.throws(() => prepareChangelog(released.content, "1.0.1", "2026-10-11"), /no release notes/);
  const second = prepareChangelog(released.content.replace("### Fixed\n", "### Fixed\n\n- Second release.\n"), "1.0.1", "2026-10-11");
  assert.equal(second.notes, "### Fixed\n\n- Second release.");
  assert.ok(second.content.startsWith(`${introduction}## [Unreleased]\n`));
  assert.ok(second.content.endsWith("## [1.0.0] - 2026-10-10\n\n### Added\n\n- First release.\n"));
});

test("prepared candidates require empty Unreleased, the current dated release and bounded notes", () => {
  const valid = `${introduction}## [Unreleased]\n\n### Added\n\n## [0.2.0] - 2026-10-21\n\n### Added\n\n- Prepared.\n\n${initial}`;
  assert.deepEqual(preparedRelease(valid, "0.2.0"), { version: "0.2.0", tag: "v0.2.0", date: "2026-10-21", notes: "### Added\n\n- Prepared." });
  assert.equal(preparedRelease(valid.replace("- Prepared.\n", "- Prepared.\n\n### Removed\n"), "0.2.0").notes, "### Added\n\n- Prepared.");
  for (const [invalid, message, version = "0.2.0"] of [
    [valid.replace("### Added\n\n## [0.2.0]", "### Added\n\n- Unreviewed change.\n\n## [0.2.0]"), /\[Unreleased\] section must be empty/],
    [valid.replace("## [0.2.0]", "## [0.1.1]"), /current \[0.2.0\] release immediately after/],
    [valid, /current \[0.1.0\] release immediately after/, "0.1.0"],
    [valid.replace("2026-10-21", "2026-02-30"), /Invalid changelog release date/],
    [valid.replace("- Prepared.\n", ""), /No release notes for 0.2.0/],
    [valid.replace("### Added\n\n- Prepared.", "- Prepared."), /0.2.0 notes must be bullets/],
    [valid.replace("## [0.2.0]", "## [Unreleased]\n\n## [0.2.0]"), /Duplicate changelog section: Unreleased/],
    [valid.replace("- Prepared.", `- ${"x".repeat(GITHUB_RELEASE_NOTES_LIMIT)}`), /GitHub permits at most/],
  ]) assert.throws(() => preparedRelease(invalid, version), message);
  const exact = valid.replace("- Prepared.", `- ${"x".repeat(GITHUB_RELEASE_NOTES_LIMIT - 13)}`);
  assert.equal(preparedRelease(exact, "0.2.0").notes.length, GITHUB_RELEASE_NOTES_LIMIT);
});
