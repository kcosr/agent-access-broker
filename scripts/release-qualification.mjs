import { parseVersion } from "./release-plan.mjs";

export const REQUIRED_RELEASE_CHECKS = Object.freeze([
  "rust-format", "crate-boundaries", "public-api", "rust-tests", "rust-build", "downstream-consumer", "rust-clippy", "unix-signals",
  "portal-dependencies", "node-tests", "rust-notice-tests", "release-prerequisite-tests", "launcher-tests",
  "audit-demo-tests", "doc-links", "changelog", "broker-sample", "broker-production-sample",
  "cli-sample", "portal-unit", "portal-build", "browser-prerequisites",
  "portal-browser", "release-provenance", "rust-notices-generate", "rust-notices-check",
]);

const FULL_OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

// A local qualification record is evidence for a release operator, not a signed
// attestation. Publication still checks the actual clean checkout and remote ref.
export function validateQualification(report, { commit, version }) {
  if (!report || report.schemaVersion !== 1 || report.status !== "passed"
      || report.sourceClean !== true || !FULL_OBJECT_ID.test(report.commit ?? "")
      || report.commit !== commit || report.version !== version) {
    throw new Error("Qualification must have passed on this exact clean commit and version");
  }
  parseVersion(version);
  if (!["linux", "darwin", "win32"].includes(report.platform)
      || !/^[a-zA-Z0-9_]+(?:-[a-zA-Z0-9_]+)+$/.test(report.target ?? "")) {
    throw new Error("Qualification must identify its native platform and target");
  }
  const started = Date.parse(report.startedAt);
  const finished = Date.parse(report.finishedAt);
  if (!Number.isFinite(started) || !Number.isFinite(finished) || finished < started) {
    throw new Error("Qualification must include valid start and completion timestamps");
  }
  if (!Array.isArray(report.checks) || report.checks.length !== REQUIRED_RELEASE_CHECKS.length) {
    throw new Error("Qualification is missing required release checks");
  }
  const checks = new Map(report.checks.map((check) => [check.id, check]));
  if (checks.size !== REQUIRED_RELEASE_CHECKS.length) {
    throw new Error("Qualification contains duplicate release checks");
  }
  for (const id of REQUIRED_RELEASE_CHECKS) {
    const check = checks.get(id);
    const notApplicable = id === "unix-signals" && report.platform === "win32";
    if (!check || (notApplicable
      ? check.status !== "not-applicable" || check.exitCode !== null
      : check.status !== "passed" || check.exitCode !== 0
        || !Array.isArray(check.command) || !check.command.length
        || check.command.some((argument) => typeof argument !== "string"))) {
      throw new Error(`Required release check did not pass: ${id}`);
    }
  }
  return report;
}
