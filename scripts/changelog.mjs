// CHANGELOG.md contract shared by the changelog check, release preparation and publication.
import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { compareVersions, parseVersion } from "./release-plan.mjs";

export const CHANGELOG_CATEGORIES = Object.freeze(["Breaking Changes", "Added", "Changed", "Fixed", "Removed"]);
export const UNRELEASED_TEMPLATE = `## [Unreleased]\n\n${CHANGELOG_CATEGORIES.map((name) => `### ${name}\n`).join("\n")}`;
export const GITHUB_RELEASE_NOTES_LIMIT = 125_000;
// The published 0.1.0 notes predate the category rule. No other section may use this heading.
const GRANDFATHERED_CATEGORIES = new Map([["0.1.0", "Initial release"]]);
const RELEASE_HEADING = /^## \[([^\]\n]+)\] - (\d{4}-\d{2}-\d{2})$/;

function sections(text) {
  const headings = [...text.matchAll(/^##(?!#)[^\n]*/gm)];
  return headings.map((heading, index) => ({ heading: heading[0], start: heading.index, end: headings[index + 1]?.index ?? text.length }));
}

function validateBody(name, body) {
  if (/^[ \t]*-[ \t]*$/m.test(body)) throw new Error(`Empty changelog note in ${name}`);
  const allowed = [...CHANGELOG_CATEGORIES, ...(GRANDFATHERED_CATEGORIES.has(name) ? [GRANDFATHERED_CATEGORIES.get(name)] : [])];
  const seen = new Set();
  let inCategory = false;
  let inNote = false;
  for (const line of body.split("\n")) {
    if (!line.trim()) continue;
    if (line.startsWith("###")) {
      const title = line.slice(4);
      if (!line.startsWith("### ") || !allowed.includes(title)) throw new Error(`Unknown changelog category in ${name}: ${line}`);
      if (seen.has(title)) throw new Error(`Duplicate changelog category in ${name}: ${title}`);
      seen.add(title);
      inCategory = true;
      inNote = false;
    } else if (inCategory && /^- \S/.test(line)) inNote = true;
    else if (!inNote || !/^ {2,}\S/.test(line)) {
      throw new Error(`${name} notes must be bullets, with indented continuation lines, under a changelog category`);
    }
  }
}

/** Notes without empty category headings; Unreleased keeps the empty template between changes. */
export function cleanNotes(body) {
  return body.split(/(?=^### )/m).filter((chunk) => !/^### [^\n]+\s*$/.test(chunk)).join("").trim();
}

/** Validate the whole file. Section offsets refer to the text with LF line endings. */
export function parseChangelog(text) {
  text = text.replace(/\r\n/g, "\n");
  if (!text.startsWith("# Changelog\n\n")) throw new Error("CHANGELOG.md must start with '# Changelog' and a blank line");
  const found = sections(text);
  if (found[0]?.heading !== "## [Unreleased]") throw new Error("The first CHANGELOG.md section must be ## [Unreleased]");
  const names = new Set();
  let previous;
  return found.map(({ heading, start, end }, index) => {
    const match = index ? RELEASE_HEADING.exec(heading) : null;
    if (index && !match && heading !== "## [Unreleased]") throw new Error(`Malformed changelog release heading: ${heading}`);
    const name = match?.[1] ?? "Unreleased";
    if (names.has(name)) throw new Error(`Duplicate changelog section: ${name}`);
    names.add(name);
    if (match) {
      try { parseVersion(name); } catch { throw new Error(`Malformed changelog release heading: ${heading}`); }
      const date = new Date(`${match[2]}T00:00:00Z`);
      if (Number.isNaN(date.valueOf()) || date.toISOString().slice(0, 10) !== match[2]) throw new Error(`Invalid changelog release date: ${match[2]}`);
      if (previous && compareVersions(name, previous) >= 0) throw new Error("Changelog releases must be in descending version order");
      previous = name;
    }
    const body = text.slice(start + heading.length, end).trim();
    validateBody(name, body);
    if (match && !cleanNotes(body)) throw new Error(`No release notes for ${name}`);
    return { name, date: match?.[2] ?? null, start, end, body, raw: text.slice(start, end) };
  });
}

function releaseNotes(body, empty) {
  const notes = cleanNotes(body);
  if (!notes) throw new Error(empty);
  const characters = [...notes].length;
  if (characters > GITHUB_RELEASE_NOTES_LIMIT) {
    throw new Error(`Release notes contain ${characters} characters; GitHub permits at most ${GITHUB_RELEASE_NOTES_LIMIT}. Shorten the release notes before releasing.`);
  }
  return notes;
}

/** Stamp Unreleased as the version without empty category headings and open a new Unreleased template. */
export function prepareChangelog(text, version, date) {
  text = text.replace(/\r\n/g, "\n");
  parseVersion(version);
  const entries = parseChangelog(text);
  if (entries.some((entry) => entry.name === version)) throw new Error(`CHANGELOG.md already contains a [${version}] section`);
  const newer = entries.slice(1).find((entry) => compareVersions(version, entry.name) <= 0);
  if (newer) throw new Error(`Release version ${version} must be newer than changelog release ${newer.name}`);
  const notes = releaseNotes(entries[0].body, "CHANGELOG.md has no release notes under [Unreleased]");
  const history = text.slice(entries[0].end);
  const content = `${text.slice(0, entries[0].start)}${UNRELEASED_TEMPLATE}\n## [${version}] - ${date}\n\n${notes}\n${history ? `\n${history}` : ""}`;
  parseChangelog(content);
  return { content, notes };
}

/** Read the already prepared release; qualification and publication use this same contract. */
export function preparedRelease(text, version) {
  parseVersion(version);
  const entries = parseChangelog(text);
  if (cleanNotes(entries[0].body)) throw new Error("Prepared changelog [Unreleased] section must be empty");
  if (entries[1]?.name !== version) throw new Error(`Prepared changelog must put the current [${version}] release immediately after [Unreleased]`);
  const notes = releaseNotes(entries[1].body, `Prepared changelog has no release notes for ${version}`);
  return { version, tag: `v${version}`, date: entries[1].date, notes };
}

export function assertReleasedNotesUnchanged(entries, baseline) {
  baseline = baseline.replace(/\r\n/g, "\n");
  const current = new Map(entries.map((entry) => [entry.name, entry.raw]));
  // Read only dated baseline sections, so a branch can correct a malformed baseline Unreleased.
  for (const { heading, start, end } of sections(baseline)) {
    const name = RELEASE_HEADING.exec(heading)?.[1];
    if (name && current.get(name) !== baseline.slice(start, end)) {
      throw new Error(`Released changelog notes for ${name} changed; put corrections under [Unreleased]`);
    }
  }
}

function localBaseline(root, env) {
  const git = (...args) => {
    const result = spawnSync("git", args, { cwd: root, env, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
    return result.status === 0 ? result.stdout : null;
  };
  // Source archives need no Git checkout or network access to validate structure.
  const top = git("rev-parse", "--show-toplevel")?.trim();
  if (!top || realpathSync(top) !== realpathSync(root)) return null;
  const head = git("rev-parse", "--verify", "HEAD")?.trim();
  if (!head) return null;
  const revision = git("merge-base", head, "refs/remotes/origin/main")?.trim() || head;
  const text = git("show", `${revision}:CHANGELOG.md`);
  if (text === null) throw new Error(`Cannot read CHANGELOG.md from local baseline ${revision}`);
  return { revision, text };
}

/** Validate structure, then compare released notes with the merge-base of HEAD and origin/main (or HEAD). */
export function checkChangelog(root, { text = readFileSync(join(root, "CHANGELOG.md"), "utf8"), env = process.env } = {}) {
  const entries = parseChangelog(text);
  const baseline = localBaseline(root, env);
  if (baseline) assertReleasedNotesUnchanged(entries, baseline.text);
  return { entries, baseline: baseline?.revision ?? null };
}
