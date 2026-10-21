import assert from "node:assert/strict";
import test from "node:test";
import { compareVersions, parseVersion, prepareVersionFiles, releaseRepository, releaseVersion, workspaceVersion } from "./release-plan.mjs";

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

test("release file parsing supports native Windows line endings and keeps workspace and registry entries distinct", () => {
  const manifest = '[workspace.package]\r\nversion = "0.1.0"\r\n\r\n[workspace.dependencies]\r\nversioned = "8"\r\n';
  const lock = 'version = 4\r\n\r\n[[package]]\r\nname = "broker"\r\nversion = "0.1.0"\r\n';
  assert.equal(workspaceVersion(manifest), "0.1.0");
  const files = prepareVersionFiles(manifest, lock, ["broker"], "0.2.0");
  assert.equal(workspaceVersion(files.manifest), "0.2.0");
  assert.match(files.manifest, /versioned = "8"/);
  assert.match(files.lock, /version = "0.2.0"/);
  assert.throws(() => prepareVersionFiles(manifest, lock, ["missing"], "0.2.0"), /entry not found/);
  assert.throws(() => prepareVersionFiles(manifest, lock.replace('version = "0.1.0"', 'version = "9.0.0"'), ["broker"], "0.2.0"), /version differs/);
});
