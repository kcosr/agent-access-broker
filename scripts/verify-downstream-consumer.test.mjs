import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  ASSEMBLY_PACKAGE, CANONICAL_PROVIDER_URL, CANONICAL_UPSTREAM_URL, CRATES_IO_SOURCE, PROVIDER_PACKAGE, SDK_PACKAGE, SENTINEL_REV,
  assertAssemblyStatus, featureViolations, gitSourceId, inheritedWorkspaceDependencies, lastTableHeader, manifestDependencies,
  normalizeProviderCrateManifest, parseConsumerArguments, parseLockfile, parseTomlValue, providerBoundaryViolations,
  reviewLockfiles, rewriteStagedManifest, sanitizedEnvironment, thirdPartyLockSeed, toolchainChannel,
} from "./verify-downstream-consumer.mjs";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const commit = "a".repeat(40);
const providerCommit = "b".repeat(40);
const upstreamUrl = "file:///stage/upstream";
const providerUrl = "file:///stage/provider";
const upstreamNames = new Set([SDK_PACKAGE, "agent-access-core", "agent-access-broker-host", "agent-access-cloudbees-ci", PROVIDER_PACKAGE]);
const upstream = { canonical: CANONICAL_UPSTREAM_URL, url: upstreamUrl, rev: commit, packages: upstreamNames };
const provider = { canonical: CANONICAL_PROVIDER_URL, url: providerUrl, rev: providerCommit, packages: new Set([PROVIDER_PACKAGE]) };
const pin = (url = CANONICAL_UPSTREAM_URL, rev = SENTINEL_REV) => `{ git = "${url}", rev = "${rev}" }`;

test("arguments require a full commit, absolute paths and a known source mode", () => {
  const args = ["--commit", commit, "--evidence-dir", "/evidence/new", "--cli", "/build/agent-access"];
  assert.deepEqual(parseConsumerArguments(args), { commit, evidenceDir: "/evidence/new", cli: "/build/agent-access", source: "staged" });
  assert.equal(parseConsumerArguments([...args, "--source", "canonical"]).source, "canonical");
  for (const invalid of [
    [], ["--commit", "abc1234", "--evidence-dir", "/e", "--cli", "/c"],
    ["--commit", commit, "--evidence-dir", "relative", "--cli", "/c"],
    ["--commit", commit, "--evidence-dir", "/e", "--cli", "agent-access"],
    [...args, "--source", "branch"], [...args, "--commit", commit], [...args, "--keep-stage"],
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
