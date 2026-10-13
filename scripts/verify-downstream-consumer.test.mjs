import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { devNull, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { inspectLocalToolchain } from "./verify-release-provenance.mjs";
import {
  ASSEMBLY_PACKAGE, CANONICAL_PROVIDER_URL, CANONICAL_UPSTREAM_URL, CRATES_IO_SOURCE, PROVIDER_PACKAGE, ProcessSupervisor, SDK_PACKAGE,
  SENTINEL_REV, assertAssemblyStatus, featureViolations, foreignCargoConfigs, gitSourceId, inheritedWorkspaceDependencies,
  isolatedGitEnvironment, lastTableHeader, manifestDependencies, normalizeProviderCrateManifest, parseConsumerArguments, parseLockfile,
  processGroupAlive,
  parseTomlValue, providerBoundaryViolations, reviewLockfiles, rewriteStagedManifest, runProcessAcceptance, sanitizedEnvironment,
  stagedCargoConfig, thirdPartyLockSeed, toolchainChannel,
} from "./verify-downstream-consumer.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const temporary = (t) => {
  const directory = mkdtempSync(join(tmpdir(), "downstream-consumer-test-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
};
const delay = (milliseconds) => new Promise((done) => setTimeout(done, milliseconds));
const waitUntil = async (condition, timeoutMs = 15_000) => {
  for (const deadline = Date.now() + timeoutMs; !condition();) {
    if (Date.now() > deadline) throw new Error("condition not reached in time");
    await delay(25);
  }
};
// A process is gone once it no longer exists or is an unreaped zombie.
const processGone = (pid) => {
  try {
    process.kill(pid, 0);
  } catch (error) {
    return error.code === "ESRCH";
  }
  try {
    return /^\d+ \(.*\) Z/.test(readFileSync(`/proc/${pid}/stat`, "utf8"));
  } catch {
    return false;
  }
};
const posixOnly = { skip: process.platform === "win32" ? "process groups and POSIX signals" : false };
const read = (path) => readFileSync(join(root, path), "utf8");
const commit = "a".repeat(40);
const providerCommit = "b".repeat(40);
const upstreamUrl = "file:///stage/upstream";
const providerUrl = "file:///stage/provider";
const upstreamNames = new Set([SDK_PACKAGE, "agent-access-core", "agent-access-broker-host", "agent-access-cloudbees-ci", PROVIDER_PACKAGE]);
const upstream = { canonical: CANONICAL_UPSTREAM_URL, url: upstreamUrl, rev: commit, packages: upstreamNames };
const provider = { canonical: CANONICAL_PROVIDER_URL, url: providerUrl, rev: providerCommit, packages: new Set([PROVIDER_PACKAGE]) };
const pin = (url = CANONICAL_UPSTREAM_URL, rev = SENTINEL_REV) => `{ git = "${url}", rev = "${rev}" }`;

test("arguments require a full commit, an absolute evidence directory and a known source mode", () => {
  const args = ["--commit", commit, "--evidence-dir", "/evidence/new"];
  assert.deepEqual(parseConsumerArguments(args), { commit, evidenceDir: "/evidence/new", source: "staged" });
  assert.equal(parseConsumerArguments([...args, "--source", "canonical"]).source, "canonical");
  for (const invalid of [
    [], ["--commit", "abc1234", "--evidence-dir", "/e"], ["--commit", commit, "--evidence-dir", "relative"],
    [...args, "--source", "branch"], [...args, "--commit", commit], [...args, "--cli", "/build/agent-access"], [...args, "--keep-stage"],
  ]) assert.throws(() => parseConsumerArguments(invalid), /Usage/);
});

test("the manifest value reader accepts only the simple single-line forms", () => {
  assert.deepEqual(parseTomlValue(`{ version = "0.12", default-features = false, features = ["json", "stream"] } # note`),
    { version: "0.12", "default-features": false, features: ["json", "stream"] });
  assert.equal(parseTomlValue(`"1.0"`), "1.0");
  assert.equal(parseTomlValue("true"), true);
  for (const value of [`{ version = "1" `, `{ a = 1, }`, `{ a = 1, a = 2 }`, `"escaped \\" quote"`, `'literal'`, `{ a.b = 1 }`, `1.5`, `"x" trailing`]) {
    assert.throws(() => parseTomlValue(value), /Unsupported manifest value/);
  }
});

test("dependency listing covers every dependency table and rejects forms that escape the checks", () => {
  const { entries } = manifestDependencies(`[package]\nname = "x"\nversion.workspace = true\n\n[dependencies]\nserde.workspace = true\n`
    + `renamed = { package = "${SDK_PACKAGE}", workspace = true }\n\n[target.'cfg(unix)'.dev-dependencies]\nlibc = "0.2"\n`
    + `\n[workspace.dependencies]\ntokio = { version = "1", features = ["rt"] }\n`);
  assert.deepEqual(entries.map((entry) => [entry.table, entry.key, entry.name]), [
    ["dependencies", "serde", "serde"], ["dependencies", "renamed", SDK_PACKAGE],
    ["target.'cfg(unix)'.dev-dependencies", "libc", "libc"], ["workspace.dependencies", "tokio", "tokio"],
  ]);
  assert.throws(() => manifestDependencies(`[patch."${CANONICAL_UPSTREAM_URL}"]\n${SDK_PACKAGE} = { path = "x" }\n`), /must not override sources/);
  assert.throws(() => manifestDependencies("[replace]\n"), /must not override sources/);
  assert.throws(() => manifestDependencies(`[dependencies.${SDK_PACKAGE}]\ngit = "${CANONICAL_UPSTREAM_URL}"\n`), /one inline dependency entry/);
  assert.throws(() => manifestDependencies(`[dependencies]\n${SDK_PACKAGE}.git = "${CANONICAL_UPSTREAM_URL}"\n`), /Unsupported dependency entry/);
  assert.throws(() => manifestDependencies(`[dependencies]\nserde.workspace = false\n`), /Unsupported dependency entry/);
  assert.equal(lastTableHeader("[a]\nx = 1\n[[bin]]\nname = \"y\"\n[workspace.dependencies]\n"), "workspace.dependencies");
});

test("staged manifests map only the canonical URL and sentinel rev to the staged sources", () => {
  const manifest = `[dependencies]\nagent-access-broker-host = ${pin()}\n${PROVIDER_PACKAGE} = ${pin(CANONICAL_PROVIDER_URL)}\n`
    + `serde = "1"\n\n[dev-dependencies]\n${SDK_PACKAGE} = { git = "${CANONICAL_UPSTREAM_URL}", rev = "${SENTINEL_REV}", features = ["test-support"] }\n`;
  const { text, rewrites } = rewriteStagedManifest(manifest, [provider, upstream]);
  assert.equal(text, `[dependencies]\nagent-access-broker-host = ${pin(upstreamUrl, commit)}\n${PROVIDER_PACKAGE} = ${pin(providerUrl, providerCommit)}\n`
    + `serde = "1"\n\n[dev-dependencies]\n${SDK_PACKAGE} = { git = "${upstreamUrl}", rev = "${commit}", features = ["test-support"] }\n`);
  assert.deepEqual(rewrites.map((rewrite) => [rewrite.package, rewrite.staged.git, rewrite.staged.rev]), [
    ["agent-access-broker-host", upstreamUrl, commit], [PROVIDER_PACKAGE, providerUrl, providerCommit], [SDK_PACKAGE, upstreamUrl, commit],
  ]);
  const canonical = rewriteStagedManifest(`[dependencies]\n${SDK_PACKAGE} = ${pin()}\n`, [{ ...upstream, url: CANONICAL_UPSTREAM_URL }]);
  assert.equal(canonical.text, `[dependencies]\n${SDK_PACKAGE} = ${pin(CANONICAL_UPSTREAM_URL, commit)}\n`);
  assert.equal(rewriteStagedManifest(`[dependencies]\n${SDK_PACKAGE}.workspace = true\n`, [upstream]).rewrites.length, 0);
});

test("any other spelling of an upstream or provider dependency is rejected", () => {
  const rejects = (line, pattern) => assert.throws(() => rewriteStagedManifest(`[dependencies]\n${line}\n`, [provider, upstream]), pattern);
  rejects(`${SDK_PACKAGE} = ${pin("https://github.com/kcosr/agent-access-broker")}`, /must use exactly/);
  rejects(`${SDK_PACKAGE} = ${pin("https://github.com/kcosr/agent-access-broker.git/")}`, /must use exactly/);
  rejects(`${SDK_PACKAGE} = ${pin(CANONICAL_UPSTREAM_URL, "0000000")}`, /sentinel rev/);
  rejects(`${SDK_PACKAGE} = ${pin(CANONICAL_UPSTREAM_URL, commit)}`, /sentinel rev/);
  rejects(`${SDK_PACKAGE} = { git = "${CANONICAL_UPSTREAM_URL}", branch = "main" }`, /must not use branch/);
  rejects(`${SDK_PACKAGE} = { git = "${CANONICAL_UPSTREAM_URL}", tag = "v0.1.0" }`, /must not use tag/);
  rejects(`${SDK_PACKAGE} = { git = "${CANONICAL_UPSTREAM_URL}" }`, /sentinel rev/);
  rejects(`${SDK_PACKAGE} = { path = "../agent-access-provider" }`, /must not use path/);
  rejects(`${SDK_PACKAGE} = "0.1.0"`, /must use https/);
  rejects(`sdk = { package = "${SDK_PACKAGE}", version = "0.1.0" }`, /must use https/);
  rejects(`${SDK_PACKAGE} = { git = "${CANONICAL_UPSTREAM_URL}", rev = "${SENTINEL_REV}", version = "0.1.0" }`, /must not combine/);
  rejects(`${PROVIDER_PACKAGE} = ${pin()}`, /must use exactly https:\/\/git\.example\.com/);
  rejects(`agent-access-core = ${pin(CANONICAL_PROVIDER_URL)}`, /must use exactly https:\/\/github\.com/);
  rejects(`serde = { git = "https://github.com/serde-rs/serde.git", rev = "${SENTINEL_REV}" }`, /must not use a git source/);
  assert.throws(() => rewriteStagedManifest(`[package]\nmetadata = "${SENTINEL_REV}"\n`, [upstream]), /sentinel rev remains/);
});

test("the provider crate is re-homed only through its SDK dependency", () => {
  const manifest = `[package]\nname = "${PROVIDER_PACKAGE}"\nversion.workspace = true\n\n[dependencies]\n`
    + `${SDK_PACKAGE} = { path = "../agent-access-provider" }\nserde.workspace = true\nurl = "2"\n\n`
    + `[dev-dependencies]\n${SDK_PACKAGE} = { path = "../agent-access-provider", features = ["test-support"] }\nwiremock.workspace = true\n`;
  const { text, inherited } = normalizeProviderCrateManifest(manifest);
  assert.equal(text, `[package]\nname = "${PROVIDER_PACKAGE}"\nversion.workspace = true\n\n[dependencies]\n`
    + `${SDK_PACKAGE}.workspace = true\nserde.workspace = true\nurl = "2"\n\n`
    + `[dev-dependencies]\n${SDK_PACKAGE} = { workspace = true, features = ["test-support"] }\nwiremock.workspace = true\n`);
  assert.deepEqual(inherited, ["serde", "wiremock"]);
  assert.throws(() => normalizeProviderCrateManifest(`[dependencies]\nagent-access-core = { path = "../agent-access-core" }\n`),
    /only through agent-access-provider; found a path dependency on agent-access-core/);
  assert.throws(() => normalizeProviderCrateManifest(`[dependencies]\n${SDK_PACKAGE} = { path = "../x", version = "0.1" }\n`), /unsupported/);
  assert.throws(() => normalizeProviderCrateManifest(`[dependencies]\nfoo = { git = "https://example.test/foo.git" }\n`), /unexpected git/);
  const root = `[workspace]\nmembers = [\n  "crates/a",\n]\n\n[workspace.dependencies]\nserde = { version = "1.0", features = ["derive"] }\nwiremock = "0.6"\n`;
  assert.deepEqual(inheritedWorkspaceDependencies(root, ["serde", "wiremock"]), ['serde = { version = "1.0", features = ["derive"] }', 'wiremock = "0.6"']);
  assert.throws(() => inheritedWorkspaceDependencies(root, ["tokio"]), /defines no workspace dependency tokio/);
  assert.throws(() => inheritedWorkspaceDependencies(`[workspace.dependencies]\nx = { path = "x" }\n`, ["x"]), /not a registry dependency/);
});

test("the checked-in templates and the maintained provider crate stage cleanly", () => {
  const providerTemplate = read("tests/downstream-consumer/provider-repo/Cargo.toml");
  const assemblyTemplate = read("tests/downstream-consumer/assembly-repo/Cargo.toml");
  assert.equal(lastTableHeader(providerTemplate), "workspace.dependencies");
  const normalized = normalizeProviderCrateManifest(read("crates/agent-access-conformance/Cargo.toml"));
  const inherited = inheritedWorkspaceDependencies(read("Cargo.toml"), normalized.inherited);
  const providerRoot = rewriteStagedManifest(`${providerTemplate.trimEnd()}\n${inherited.join("\n")}\n`, [upstream]);
  assert.deepEqual(providerRoot.rewrites.map((rewrite) => rewrite.package), [SDK_PACKAGE]);
  assert.equal(rewriteStagedManifest(normalized.text, [upstream]).rewrites.length, 0);
  const assembly = rewriteStagedManifest(assemblyTemplate, [provider, upstream]);
  assert.deepEqual(assembly.rewrites.map((rewrite) => rewrite.package), ["agent-access-broker-host", "agent-access-cloudbees-ci", PROVIDER_PACKAGE]);
  assert.match(assemblyTemplate, new RegExp(`^name = "${ASSEMBLY_PACKAGE}"$`, "m"));
  const pinned = toolchainChannel(read("rust-toolchain.toml"));
  for (const path of ["tests/downstream-consumer/provider-repo/rust-toolchain.toml", "tests/downstream-consumer/assembly-repo/rust-toolchain.toml"]) {
    assert.equal(toolchainChannel(read(path)), pinned, path);
  }
  for (const template of [providerTemplate, assemblyTemplate]) {
    assert.match(template, /^\[profile\.dev\]\ndebug = false\nincremental = false$/m);
  }
});

const lockText = (packages) => `# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n${packages.map((entry) =>
  `\n[[package]]\nname = "${entry.name}"\nversion = "${entry.version}"\n${entry.source ? `source = "${entry.source}"\n` : ""}`
  + `${entry.checksum ? `checksum = "${entry.checksum}"\n` : ""}${entry.dependencies ? `dependencies = [\n${entry.dependencies.map((name) => ` "${name}",\n`).join("")}]\n` : ""}`).join("")}`;
const checksum = (character) => character.repeat(64);
const candidateLock = lockText([
  { name: "agent-access-broker", version: "0.1.0", dependencies: [SDK_PACKAGE, "serde"] },
  { name: "agent-access-broker-host", version: "0.1.0" },
  { name: PROVIDER_PACKAGE, version: "0.1.0" },
  { name: SDK_PACKAGE, version: "0.1.0", dependencies: ["serde"] },
  { name: "serde", version: "1.0.200", source: CRATES_IO_SOURCE, checksum: checksum("1"), dependencies: ["serde_derive"] },
  { name: "serde_derive", version: "1.0.200", source: CRATES_IO_SOURCE, checksum: checksum("2") },
]);

test("lockfiles parse and seed only the candidate's third-party entries", () => {
  const lock = parseLockfile(candidateLock);
  assert.equal(lock.packages.length, 6);
  assert.deepEqual(lock.packages[0].dependencies, [SDK_PACKAGE, "serde"]);
  assert.equal(lock.packages[4].checksum, checksum("1"));
  const seed = parseLockfile(thirdPartyLockSeed(candidateLock));
  assert.deepEqual(seed.packages.map((entry) => entry.name), ["serde", "serde_derive"]);
  assert.deepEqual(seed.packages[0].dependencies, ["serde_derive"]);
  assert.throws(() => parseLockfile("version = 3\n"), /format version 3/);
  assert.throws(() => thirdPartyLockSeed(lockText([{ name: "x", version: "1.0.0", source: "git+https://example.test/x.git#abc" }])), /unsupported sources/);
  const real = parseLockfile(read("Cargo.lock"));
  assert.ok(real.packages.some((entry) => entry.name === SDK_PACKAGE && entry.source === null));
  assert.ok(parseLockfile(thirdPartyLockSeed(read("Cargo.lock"))).packages.every((entry) => entry.source === CRATES_IO_SOURCE));
});

test("lockfile review requires exact sources, one SDK identity and candidate third-party versions", () => {
  const upstreamSource = gitSourceId(upstreamUrl, commit);
  const providerSource = gitSourceId(providerUrl, providerCommit);
  assert.equal(upstreamSource, `git+${upstreamUrl}?rev=${commit}#${commit}`);
  const providerLock = [
    { name: PROVIDER_PACKAGE, version: "0.7.0" },
    { name: SDK_PACKAGE, version: "0.1.0", source: upstreamSource },
    { name: "serde", version: "1.0.200", source: CRATES_IO_SOURCE, checksum: checksum("1") },
  ];
  const assemblyLock = [
    { name: ASSEMBLY_PACKAGE, version: "0.3.0" },
    { name: "agent-access-broker-host", version: "0.1.0", source: upstreamSource },
    { name: PROVIDER_PACKAGE, version: "0.7.0", source: providerSource },
    { name: SDK_PACKAGE, version: "0.1.0", source: upstreamSource },
    { name: "serde_derive", version: "1.0.200", source: CRATES_IO_SOURCE, checksum: checksum("2") },
  ];
  const review = (providerPackages, assemblyPackages) => reviewLockfiles({ candidate: parseLockfile(candidateLock),
    staged: [{ repository: "provider", lock: parseLockfile(lockText(providerPackages)), members: [PROVIDER_PACKAGE] },
      { repository: "assembly", lock: parseLockfile(lockText(assemblyPackages)), members: [ASSEMBLY_PACKAGE] }],
    upstreamSource, providerSource });
  const passing = review(providerLock, assemblyLock);
  assert.deepEqual(passing.errors, []);
  assert.deepEqual(passing.sdkPackageIds, [`${SDK_PACKAGE} 0.1.0 ${upstreamSource}`]);
  assert.deepEqual(passing.summary.map((entry) => [entry.repository, entry.workspace, entry.upstream, entry.provider, entry.thirdParty]),
    [["provider", 1, 1, 0, 1], ["assembly", 1, 2, 1, 1]]);
  const withEntry = (packages, index, change) => packages.map((entry, position) => (position === index ? { ...entry, ...change } : entry));
  const failures = [
    [review(withEntry(providerLock, 1, { source: gitSourceId(upstreamUrl.replace("upstream", "other"), commit) }), assemblyLock), /does not resolve to/],
    [review(providerLock, [...assemblyLock, { name: SDK_PACKAGE, version: "0.1.0", source: `git+${upstreamUrl}?branch=main#${commit}` }]), /exactly one agent-access-provider package ID/],
    [review(providerLock, withEntry(assemblyLock, 3, { source: CRATES_IO_SOURCE, checksum: checksum("3") })), /does not resolve to/],
    [review(providerLock, [...assemblyLock, { name: "agent-access-core", version: "0.1.0" }]), /path package outside the staged workspace/],
    [review(providerLock, withEntry(assemblyLock, 2, { source: upstreamSource })), /must come from the provider repository/],
    [review(providerLock, withEntry(assemblyLock, 4, { version: "1.0.201" })), /not in the candidate Cargo\.lock/],
    [review(providerLock, withEntry(assemblyLock, 4, { checksum: checksum("9") })), /checksum differs/],
    [review(providerLock, [...assemblyLock, { name: "left-pad", version: "1.0.0", source: "git+https://example.test/left-pad.git#abc" }]), /unexpected source/],
    [review(providerLock.filter((entry) => entry.name !== PROVIDER_PACKAGE), assemblyLock), /member agent-access-conformance is missing/],
    [review(providerLock, withEntry(assemblyLock, 1, { name: "agent-access-unknown" })), /not a candidate workspace package/],
  ];
  for (const [result, pattern] of failures) assert.ok(result.errors.some((error) => pattern.test(error)), `${pattern}: ${result.errors.join("; ")}`);
});

test("graph checks reject release test support and forbidden provider edges", () => {
  const tree = `downstream-broker v0.3.0 (/stage/assembly)\n├── agent-access-provider feature "default"\n│   └── agent-access-provider feature "test-support"\n`;
  assert.deepEqual(featureViolations(tree), ['│   └── agent-access-provider feature "test-support"']);
  assert.deepEqual(featureViolations(tree.replace(/test-support/g, "rustls")), []);
  const role = (name, value) => ({ name, version: "0.1.0", metadata: value ? { "agent-access": { role: value } } : null });
  assert.deepEqual(providerBoundaryViolations({ packages: [role(PROVIDER_PACKAGE, "reference"), role(SDK_PACKAGE, "sdk"), role("serde")] }), []);
  assert.deepEqual(providerBoundaryViolations({ packages: [role("agent-access-core", "core"), role("agent-access-broker-host", "host"),
    role("agent-access-mcp-upstream", "adapter")] }).length, 3);
});

test("status identity and environment sanitization", () => {
  assertAssemblyStatus({ brokerVersion: "0.3.0", buildCommit: null, buildProvenance: "unavailable", catalogVersion: "x" }, { version: "0.3.0" });
  for (const status of [{ brokerVersion: "0.1.0", buildProvenance: "unavailable" }, { brokerVersion: "0.3.0", buildProvenance: "release", buildCommit: commit }, null]) {
    assert.throws(() => assertAssemblyStatus(status, { version: "0.3.0" }), /assembly's own version/);
  }
  const { env, removed } = sanitizedEnvironment({ PATH: "/bin", HOME: "/home/x", CARGO_HOME: "/c", CARGO_TARGET_DIR: "/t", CARGO_PROFILE_DEV_DEBUG: "0",
    RUSTFLAGS: "-C x", RUSTC_WRAPPER: "sccache", RUSTUP_TOOLCHAIN: "nightly", CC: "clang", AGENT_ACCESS_BROKER_CONFIG: "/x", RUSTUP_HOME: "/r",
    CARGO_BUILD_JOBS: "4" });
  assert.deepEqual(env, { PATH: "/bin", HOME: "/home/x", RUSTUP_HOME: "/r", CARGO_BUILD_JOBS: "4" });
  assert.deepEqual(removed, ["AGENT_ACCESS_BROKER_CONFIG", "CARGO_HOME", "CARGO_PROFILE_DEV_DEBUG", "CARGO_TARGET_DIR", "CC", "RUSTC_WRAPPER", "RUSTFLAGS", "RUSTUP_TOOLCHAIN"]);
});

test("the private Cargo home replaces crates.io with the cache directory and fetches Git through the CLI", () => {
  const config = stagedCargoConfig("/stage/registry");
  assert.match(config, /^\[source\.crates-io\]\nreplace-with = "shared-download-cache"$/m);
  assert.match(config, /^\[source\.shared-download-cache\]\ndirectory = "\/stage\/registry"$/m);
  assert.match(config, /^\[net\]\ngit-fetch-with-cli = true$/m);
  const env = isolatedGitEnvironment({ PATH: "/bin", HOME: "/home/user" }, { home: "/stage/home", protocols: "file" });
  assert.deepEqual(env, { PATH: "/bin", HOME: "/stage/home", XDG_CONFIG_HOME: "/stage/home/.config", GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: devNull, GIT_TERMINAL_PROMPT: "0", GIT_ALLOW_PROTOCOL: "file" });
});

test("every Cargo configuration besides the private one is foreign, including ancestors and legacy names", (t) => {
  const directory = temporary(t);
  const ancestor = join(directory, "ancestor");
  const repository = join(ancestor, "stage", "repository");
  const cargoHome = join(ancestor, "stage", "cargo-home");
  for (const path of [join(ancestor, ".cargo"), join(repository, ".cargo"), cargoHome]) mkdirSync(path, { recursive: true });
  writeFileSync(join(cargoHome, "config.toml"), stagedCargoConfig(join(ancestor, "stage", "registry")));
  assert.ok(!foreignCargoConfigs(repository, cargoHome).some((config) => config.path.startsWith(ancestor)));
  writeFileSync(join(ancestor, ".cargo", "config.toml"), 'source.crates-io.replace-with = "elsewhere"\ninclude = "more.toml"\n');
  writeFileSync(join(repository, ".cargo", "config"), '[build]\ntarget-dir = "/elsewhere"\n');
  const foreign = foreignCargoConfigs(repository, cargoHome).map((config) => config.path);
  assert.ok(foreign.includes(join(ancestor, ".cargo", "config.toml")));
  assert.ok(foreign.includes(join(repository, ".cargo", "config")));
  assert.ok(!foreign.includes(join(cargoHome, "config.toml")));
});

test("a global Git URL rewrite cannot redirect staged Cargo fetches, and other transports are refused", (t) => {
  const directory = temporary(t);
  const quiet = { ...sanitizedEnvironment(process.env).env, GIT_CONFIG_GLOBAL: devNull, GIT_CONFIG_NOSYSTEM: "1" };
  const git = (cwd, args, env = quiet) => execFileSync("git", args, { cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  const repository = (name, version) => {
    const path = join(directory, name);
    mkdirSync(join(path, "src"), { recursive: true });
    writeFileSync(join(path, "Cargo.toml"), `[package]\nname = "staged-dependency"\nversion = "${version}"\nedition = "2024"\n\n[workspace]\n`);
    writeFileSync(join(path, "src", "lib.rs"), "");
    git(path, ["init", "--quiet", "--initial-branch=main"]);
    git(path, ["add", "--all"]);
    git(path, ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", name]);
    return { url: pathToFileURL(path).href, commit: git(path, ["rev-parse", "HEAD"]) };
  };
  const dependency = repository("dependency", "1.0.0");
  const decoy = repository("decoy", "2.0.0");
  const userHome = join(directory, "user-home");
  mkdirSync(userHome);
  writeFileSync(join(userHome, ".gitconfig"), `[url "${decoy.url}"]\n\tinsteadOf = ${dependency.url}\n`);
  const userEnv = { ...sanitizedEnvironment(process.env).env, HOME: userHome, XDG_CONFIG_HOME: join(userHome, ".config") };
  for (const name of Object.keys(userEnv)) if (name.startsWith("GIT_")) delete userEnv[name];
  // An ordinary Git client follows the user's rewrite to the decoy.
  assert.equal(git(directory, ["ls-remote", dependency.url, "HEAD"], userEnv).split("\t")[0], decoy.commit);

  const stageHome = join(directory, "stage-home");
  const cargoHome = join(directory, "cargo-home");
  const consumer = join(directory, "consumer");
  for (const path of [stageHome, cargoHome, join(directory, "registry"), join(consumer, "src")]) mkdirSync(path, { recursive: true });
  writeFileSync(join(cargoHome, "config.toml"), stagedCargoConfig(join(directory, "registry")));
  writeFileSync(join(consumer, "Cargo.toml"), `[package]\nname = "staged-consumer"\nversion = "0.1.0"\nedition = "2024"\n\n`
    + `[dependencies]\nstaged-dependency = { git = "${dependency.url}", rev = "${dependency.commit}" }\n\n[workspace]\n`);
  writeFileSync(join(consumer, "src", "lib.rs"), "");
  const toolchain = inspectLocalToolchain(root, { env: sanitizedEnvironment(process.env).env });
  const env = { ...isolatedGitEnvironment(userEnv, { home: stageHome, protocols: "file" }), CARGO_HOME: cargoHome, RUSTC: toolchain.rustcPath };
  execFileSync(toolchain.cargoPath, ["fetch"], { cwd: consumer, env, stdio: ["ignore", "pipe", "pipe"] });
  const fetched = parseLockfile(readFileSync(join(consumer, "Cargo.lock"), "utf8")).packages.find((entry) => entry.name === "staged-dependency");
  assert.equal(fetched.version, "1.0.0");
  assert.equal(fetched.source, gitSourceId(dependency.url, dependency.commit));
  assert.throws(() => git(directory, ["ls-remote", "https://example.invalid/repository.git"], env), /transport 'https' not allowed/);
});

test("interrupting a supervised build stops its whole process tree and refuses new work", posixOnly, async (t) => {
  const directory = temporary(t);
  const pids = join(directory, "pids");
  const script = join(directory, "build.mjs");
  writeFileSync(script, `import { spawn } from "node:child_process";
import { renameSync, writeFileSync } from "node:fs";
const compiler = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
writeFileSync(process.argv[2] + ".partial", process.pid + " " + compiler.pid);
renameSync(process.argv[2] + ".partial", process.argv[2]);
setInterval(() => {}, 1000);
`);
  const supervisor = new ProcessSupervisor({ graceMs: 2_000 });
  const build = supervisor.run(process.execPath, [script, pids]);
  build.catch(() => {});
  await waitUntil(() => existsSync(pids));
  const [leader, compiler] = readFileSync(pids, "utf8").split(" ").map(Number);
  await supervisor.interrupt("SIGINT");
  await assert.rejects(build, { name: "InterruptedError", signal: "SIGINT" });
  await waitUntil(() => processGone(leader) && processGone(compiler));
  assert.equal(supervisor.interruption, "SIGINT");
  await assert.rejects(supervisor.run(process.execPath, ["-e", ""]), { name: "InterruptedError" });
});

test("a process that ignores SIGTERM is killed after the grace period", posixOnly, async (t) => {
  const directory = temporary(t);
  const pid = join(directory, "pid");
  const script = join(directory, "stubborn.mjs");
  writeFileSync(script, `import { renameSync, writeFileSync } from "node:fs";
process.on("SIGTERM", () => {});
writeFileSync(process.argv[2] + ".partial", String(process.pid));
renameSync(process.argv[2] + ".partial", process.argv[2]);
setInterval(() => {}, 1000);
`);
  const supervisor = new ProcessSupervisor({ graceMs: 300 });
  const running = supervisor.run(process.execPath, [script, pid]);
  running.catch(() => {});
  await waitUntil(() => existsSync(pid));
  await supervisor.interrupt("SIGTERM");
  await assert.rejects(running, { name: "InterruptedError" });
  assert.ok(processGone(Number(readFileSync(pid, "utf8"))));
});

test("interrupting broker acceptance stops the broker and the synthetic controller", posixOnly, async (t) => {
  const directory = temporary(t);
  const broker = join(directory, "stand-in-broker.mjs");
  writeFileSync(broker, `#!/usr/bin/env node
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
const args = process.argv.slice(2);
const config = readFileSync(args[1], "utf8");
if (args[2] === "config") {
  if (config.includes("enable_fake_service = false")) {
    process.stderr.write("- providers.conformance is a development backend\\n");
    process.exit(3);
  }
  process.exit(0);
}
const [host, port] = args[4].split(":");
createServer((request, response) => { response.writeHead(503); response.end(); }).listen(Number(port), host, () => {
  writeFileSync("broker.pid.partial", String(process.pid));
  renameSync("broker.pid.partial", "broker.pid");
});
`);
  chmodSync(broker, 0o755);
  const run = join(directory, "run");
  const evidence = join(directory, "evidence");
  const supervisor = new ProcessSupervisor({ graceMs: 2_000 });
  const acceptance = runProcessAcceptance({ supervisor, binary: broker, cli: join(directory, "unused-cli"), run, evidence,
    env: sanitizedEnvironment(process.env).env, version: "0.3.0" });
  acceptance.catch(() => {});
  await waitUntil(() => existsSync(join(run, "broker.pid")));
  const pid = Number(readFileSync(join(run, "broker.pid"), "utf8"));
  const controller = /base_url = "(http:\/\/127\.0\.0\.1:\d+)\/team-ci\/"/.exec(readFileSync(join(run, "broker.toml"), "utf8"))[1];
  assert.equal((await fetch(`${controller}/unknown`)).status, 404);
  await supervisor.interrupt("SIGTERM");
  await assert.rejects(acceptance, { name: "InterruptedError", signal: "SIGTERM" });
  await waitUntil(() => processGone(pid));
  await assert.rejects(fetch(`${controller}/unknown`), /fetch failed/);
  assert.ok(existsSync(join(evidence, "acceptance", "broker.log")));
});

// A leader that starts one descendant in its own process group and waits
// until the descendant is ready. The descendant writes its pid once it has
// installed its signal handling; `leader` decides what the leader does next.
const leaderScript = (directory, { ignoreTerm, leader }) => {
  const script = join(directory, "leader.mjs");
  const descendant = `${ignoreTerm ? 'process.on("SIGTERM", () => {});' : ""}`
    + 'require("node:fs").writeFileSync(process.argv[1] + ".partial", String(process.pid));'
    + 'require("node:fs").renameSync(process.argv[1] + ".partial", process.argv[1]);'
    + "setInterval(() => {}, 1000);";
  writeFileSync(script, `import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
const ready = process.argv[2];
spawn(process.execPath, ["-e", ${JSON.stringify(descendant)}, ready], { stdio: "inherit" }).unref();
const wait = () => (existsSync(ready) ? (${leader})() : setTimeout(wait, 10));
wait();
`);
  return script;
};
const exitLeader = "() => process.exit(0)";
const stayLeader = "() => setInterval(() => {}, 1000)";

test("a leader that exits first does not release descendants still running in its group", posixOnly, async (t) => {
  for (const ignoreTerm of [false, true]) {
    const directory = temporary(t);
    const ready = join(directory, "descendant.pid");
    const log = openSync(join(directory, "output.log"), "w");
    const supervisor = new ProcessSupervisor({ graceMs: 300 });
    try {
      // The descendant inherits the file-backed output, so the leader's close
      // does not wait for it.
      const result = await supervisor.run(process.execPath, [leaderScript(directory, { ignoreTerm, leader: exitLeader }), ready],
        { stdout: log, stderr: log });
      assert.equal(result.code, 0);
      const descendant = Number(readFileSync(ready, "utf8"));
      assert.ok(processGone(descendant), `descendant ${descendant} survived run() (ignoreTerm=${ignoreTerm})`);
      assert.equal(supervisor.strays.length, 1);
      assert.ok(!processGroupAlive(supervisor.strays[0].processGroup));
    } finally {
      closeSync(log);
    }
  }
});

test("a timed-out run returns only after its SIGTERM-ignoring descendants are stopped", posixOnly, async (t) => {
  const directory = temporary(t);
  const ready = join(directory, "descendant.pid");
  const supervisor = new ProcessSupervisor({ graceMs: 300 });
  const result = await supervisor.run(process.execPath, [leaderScript(directory, { ignoreTerm: true, leader: stayLeader }), ready],
    { timeoutMs: 1_000 });
  assert.equal(result.timedOut, true);
  assert.notEqual(result.code, 0);
  assert.ok(processGone(Number(readFileSync(ready, "utf8"))));
});

test("an interruption stops descendants of a started process whose leader already exited", posixOnly, async (t) => {
  const directory = temporary(t);
  const ready = join(directory, "descendant.pid");
  const supervisor = new ProcessSupervisor({ graceMs: 300 });
  const record = supervisor.start(process.execPath, [leaderScript(directory, { ignoreTerm: true, leader: exitLeader }), ready]);
  assert.equal((await record.closed).code, 0);
  const descendant = Number(readFileSync(ready, "utf8"));
  assert.ok(!processGone(descendant));
  await supervisor.interrupt("SIGTERM");
  assert.ok(processGone(descendant));
  await supervisor.stopAll();
});
