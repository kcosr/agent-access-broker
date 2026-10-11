// These overrides can make Git describe a different tree/index from the source
// being compiled. Never log their values: config overrides may contain secrets.
const GIT_LOCATION_OVERRIDES = new Set([
  "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
  "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CONFIG",
]);

export function assertNoGitOverrides(env = process.env) {
  const overrides = Object.keys(env).filter((name) => env[name] !== undefined && env[name] !== ""
    && (GIT_LOCATION_OVERRIDES.has(name) || name.startsWith("GIT_CONFIG_")));
  if (overrides.length) throw new Error(`Unset Git repository/index/config overrides for release work: ${overrides.sort().join(", ")}`);
}
