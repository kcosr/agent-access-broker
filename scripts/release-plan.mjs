// Pure release preparation: validate everything before writing tracked files.
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
export const GITHUB_RELEASE_NOTES_LIMIT = 125_000;

/** Bind GitHub actions to origin, independently of a caller's GH_REPO setting. */
export function releaseRepository(remote) {
  let host;
  let pathname;
  const scp = remote.match(/^(?:[^@/:]+@)?([^/:]+):([^/].*)$/);
  if (scp && !remote.includes("://")) {
    host = scp[1];
    pathname = scp[2];
  } else {
    try {
      const url = new URL(remote);
      if (!["https:", "http:", "ssh:", "git:"].includes(url.protocol)) throw new Error();
      host = url.hostname;
      pathname = url.pathname.replace(/^\//, "");
    } catch { throw new Error("origin must identify a hosted owner/repository for GitHub releases"); }
  }
  pathname = pathname.replace(/\.git$/, "");
  if (!/^[A-Za-z0-9.-]+$/.test(host) || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(pathname)) throw new Error("origin must identify a hosted owner/repository for GitHub releases");
  return `${host}/${pathname}`;
}

export function parseVersion(value) {
  const match = VERSION.exec(value);
  if (!match || match[4]?.split(".").some((part) => /^\d+$/.test(part) && part.length > 1 && part.startsWith("0"))) {
    throw new Error(`Invalid semantic version: ${value}`);
  }
  return { numbers: match.slice(1, 4).map(BigInt), prerelease: match[4]?.split(".") ?? [] };
}

export function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  for (let i = 0; i < 3; i++) {
    if (a.numbers[i] !== b.numbers[i]) return a.numbers[i] > b.numbers[i] ? 1 : -1;
  }
  if (!a.prerelease.length || !b.prerelease.length) return Number(!a.prerelease.length) - Number(!b.prerelease.length);
  for (let i = 0; i < Math.max(a.prerelease.length, b.prerelease.length); i++) {
    const x = a.prerelease[i];
    const y = b.prerelease[i];
    if (x === y) continue;
    if (x === undefined || y === undefined) return x === undefined ? -1 : 1;
    const numericX = /^\d+$/.test(x);
    const numericY = /^\d+$/.test(y);
    if (numericX !== numericY) return numericX ? -1 : 1;
    return (numericX ? BigInt(x) > BigInt(y) : x > y) ? 1 : -1;
  }
  return 0;
}

export function releaseVersion(current, argument) {
  const parts = parseVersion(current).numbers;
  if (argument === "current") return current;
  const index = ["major", "minor", "patch"].indexOf(argument);
  let next = argument;
  if (index !== -1) {
    parts[index] += 1n;
    for (let i = index + 1; i < parts.length; i++) parts[i] = 0n;
    next = parts.join(".");
  }
  if (compareVersions(next, current) <= 0) throw new Error(`Release version ${next} must be newer than ${current}; use current to release the existing version`);
  return next;
}

export function prepareChangelog(content, version, date) {
  content = content.replace(/\r\n/g, "\n");
  parseVersion(version);
  if (!content.startsWith("# Changelog\n\n")) throw new Error("CHANGELOG.md must start with '# Changelog' and a blank line");
  const sections = content.match(/^## \[Unreleased\]$/gm) ?? [];
  if (sections.length !== 1) throw new Error("CHANGELOG.md must have exactly one [Unreleased] section");
  if (content.split("\n").some((line) => line.startsWith(`## [${version}]`))) throw new Error(`CHANGELOG.md already contains a [${version}] section`);
  const match = content.match(/## \[Unreleased\]\n([\s\S]*?)(?=\n## \[|$)/);
  const notes = match?.[1].trim();
  if (!notes || !/^-\s+\S/m.test(notes)) throw new Error("CHANGELOG.md has no release notes under [Unreleased]");
  validateReleaseNotes(notes);
  return { content: content.replace(/^## \[Unreleased\]$/m, `## [${version}] - ${date}`), notes };
}

function validateReleaseNotes(notes) {
  if (!notes || !/^-\s+\S/m.test(notes)) throw new Error("Release notes must contain a nonempty change list");
  const characters = [...notes].length;
  if (characters > GITHUB_RELEASE_NOTES_LIMIT) {
    throw new Error(`Release notes contain ${characters} characters; GitHub permits at most ${GITHUB_RELEASE_NOTES_LIMIT}. Shorten the release notes before releasing.`);
  }
}

/** Read the already prepared release; qualification and publication use this same contract. */
export function preparedRelease(content, version) {
  content = content.replace(/\r\n/g, "\n");
  parseVersion(version);
  if (!content.startsWith("# Changelog\n\n")) throw new Error("CHANGELOG.md must start with '# Changelog' and a blank line");
  const sections = [...content.matchAll(/^## \[([^\]\n]+)\]([^\n]*)$/gm)];
  if (sections[0]?.[1] !== "Unreleased" || sections[0][2] !== ""
      || sections.filter((section) => section[1] === "Unreleased").length !== 1) {
    throw new Error("Prepared changelog must start with exactly one [Unreleased] section");
  }
  if (sections[1]?.[1] !== version || sections.filter((section) => section[1] === version).length !== 1) {
    throw new Error(`Prepared changelog must put the current [${version}] release immediately after [Unreleased]`);
  }
  const date = /^ - (\d{4}-\d{2}-\d{2})$/.exec(sections[1][2])?.[1];
  if (!date || !Number.isFinite(Date.parse(date)) || new Date(date).toISOString().slice(0, 10) !== date) {
    throw new Error("Prepared release must have a valid YYYY-MM-DD date");
  }
  const unreleased = content.slice(sections[0].index + sections[0][0].length, sections[1].index);
  if (unreleased.split("\n").some((line) => line.trim() && !/^### (Breaking Changes|Added|Changed|Fixed|Removed)$/.test(line))) {
    throw new Error("Prepared changelog [Unreleased] section must be empty");
  }
  const notes = content.slice(sections[1].index + sections[1][0].length, sections[2]?.index ?? content.length).trim();
  validateReleaseNotes(notes);
  return { version, tag: `v${version}`, date, notes };
}

export function workspaceVersion(manifest) {
  manifest = manifest.replace(/\r\n/g, "\n");
  const section = manifest.match(/^\[workspace\.package\][ \t]*\n([\s\S]*?)(?=^\[|(?![\s\S]))/m)?.[1];
  const versions = [...(section ?? "").matchAll(/^version[ \t]*=[ \t]*"([^"]+)"[ \t]*$/gm)];
  if (versions.length !== 1) throw new Error("Cargo.toml must have one [workspace.package] version");
  parseVersion(versions[0][1]);
  return versions[0][1];
}

export function prepareVersionFiles(manifest, lock, packageNames, version) {
  manifest = manifest.replace(/\r\n/g, "\n");
  lock = lock.replace(/\r\n/g, "\n");
  const current = workspaceVersion(manifest);
  parseVersion(version);
  if (!packageNames.length || new Set(packageNames).size !== packageNames.length) throw new Error("Workspace package names must be nonempty and unique");
  const found = new Set();
  const updatedLock = lock.replace(/^\[\[package\]\]\n[\s\S]*?(?=^\[\[package\]\]|$(?![\s\S]))/gm, (entry) => {
    const name = /^name = "([^"]+)"$/m.exec(entry)?.[1];
    if (!packageNames.includes(name) || /^source\s*=/m.test(entry)) return entry;
    if (found.has(name)) throw new Error(`Cargo.lock has duplicate workspace entries for ${name}`);
    found.add(name);
    const entryVersion = /^version = "([^"]+)"$/m.exec(entry)?.[1];
    if (entryVersion !== current) throw new Error(`Cargo.lock workspace version differs for ${name}`);
    return entry.replace(/^version = "[^"]+"$/m, `version = "${version}"`);
  });
  for (const name of packageNames) if (!found.has(name)) throw new Error(`Cargo.lock workspace package entry not found for ${name}`);
  const updatedManifest = manifest.replace(/(^\[workspace\.package\][ \t]*\n[\s\S]*?)(?=^\[|(?![\s\S]))/m,
    (section) => section.replace(/^version[ \t]*=[ \t]*"[^"]+"[ \t]*$/m, `version = "${version}"`));
  return { manifest: updatedManifest, lock: updatedLock };
}

export function nextCycleChangelog(content) {
  content = content.replace(/\r\n/g, "\n");
  if (!content.startsWith("# Changelog\n\n") || /^## \[Unreleased\]$/m.test(content)) throw new Error("Released changelog cannot open a new [Unreleased] section");
  const firstRelease = /^## \[/m.exec(content);
  if (!firstRelease) throw new Error("Released changelog must contain a release section");
  const nextCycle = "## [Unreleased]\n\n### Breaking Changes\n\n### Added\n\n### Changed\n\n### Fixed\n\n### Removed\n\n";
  return content.slice(0, firstRelease.index) + nextCycle + content.slice(firstRelease.index);
}
