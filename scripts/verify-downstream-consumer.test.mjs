import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { devNull, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { BROKER_LOG_FILTER, inspectLocalToolchain } from "./verify-release-provenance.mjs";
import {
  ASSEMBLY_GUIDE, ASSEMBLY_GUIDE_SHARED_FILES, ASSEMBLY_PACKAGE, CANONICAL_PROVIDER_URL, CANONICAL_UPSTREAM_URL, CRATES_IO_SOURCE, FIXTURE_QUALIFICATION,
  GUIDE_PROVIDER_URL, GUIDE_SNIPPET_PACKAGE, PROVIDER_GUIDE, PROVIDER_PACKAGE, compiledSourceFiles, dependencyInfoFiles,
  ProcessSupervisor, SDK_PACKAGE, SENTINEL_REV, assertAssemblyStatus, assertStartingEvent, assemblyFeatureTreeArgs, assemblyFeatureViolations, expectedAssemblyStatus, extractGuide,
  foreignCargoConfigs, gitSourceId, guideBlockMarker, guideExamples, guideManifestPins, inheritedWorkspaceDependencies,
  inventoryFingerprint, isolatedGitEnvironment, lastTableHeader, manifestDependencies, manifestPackageField, markdownCodeBlocks, normalizeProviderCrateManifest,
  parseConsumerArguments, parseLockfile, processGroupAlive,
  parseTomlValue, providerBoundaryViolations, reviewLockfiles, rewriteStagedManifest, runProcessAcceptance, sanitizedEnvironment, sharedAssemblyFiles,
  snippetCrate, stagedCargoConfig, thirdPartyLockSeed, toolchainChannel, unmarkedRustBlocks,
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
  assert.deepEqual(assembly.rewrites.map((rewrite) => [rewrite.table, rewrite.package]), [["dependencies", "agent-access-broker-host"],
    ["dependencies", "agent-access-cloudbees-ci"], ["dependencies", PROVIDER_PACKAGE], ["dev-dependencies", "agent-access-broker-host"]]);
  assert.match(assemblyTemplate, new RegExp(`^name = "${ASSEMBLY_PACKAGE}"$`, "m"));
  const pinned = toolchainChannel(read("rust-toolchain.toml"));
  for (const path of ["tests/downstream-consumer/provider-repo/rust-toolchain.toml", "tests/downstream-consumer/assembly-repo/rust-toolchain.toml"]) {
    assert.equal(toolchainChannel(read(path)), pinned, path);
  }
  for (const template of [providerTemplate, assemblyTemplate]) {
    assert.match(template, /^\[profile\.dev\]\ndebug = false\nincremental = false$/m);
  }
});

const fence = (info, body) => `\`\`\`${info}\n${body}\`\`\`\n`;
const exampleManifest = (name, extra = "") => `[package]\nname = "${name}"\nversion = "0.1.0"\nedition = "2024"\n\n[dependencies]\n`
  + `${SDK_PACKAGE} = { git = "${CANONICAL_UPSTREAM_URL}", rev = "<full 40-character commit>" }\n${extra}`;

test("Markdown code blocks keep their fence line, info string and lines, including indented and tilde fences", () => {
  const text = "# Title\n\n```rust check\nfn a() {}\n```\n\n- item\n\n  ```toml file=x/Cargo.toml\n  [package]\n    name = \"x\"\n  ```\n\n"
    + "~~~~text\n```\nnot a fence\n~~~\n~~~~~\n\n``` inline `code` ```\n```\n\n```\n";
  assert.deepEqual(markdownCodeBlocks(text), [
    { line: 3, info: "rust check", language: "rust", attributes: ["check"], container: null, text: "fn a() {}\n" },
    { line: 9, info: "toml file=x/Cargo.toml", language: "toml", attributes: ["file=x/Cargo.toml"], container: null, text: "[package]\n  name = \"x\"\n" },
    { line: 14, info: "text", language: "text", attributes: [], container: null, text: "```\nnot a fence\n~~~\n" },
    { line: 21, info: "", language: "", attributes: [], container: null, text: "\n" },
  ]);
  assert.throws(() => markdownCodeBlocks("```rust check\nfn a() {}\n"), /opened at line 1 is not closed/);
  assert.deepEqual(markdownCodeBlocks("-\titem\n\n\t```rust check\n\tfn a() {}\n\t```\n"),
    [{ line: 3, info: "rust check", language: "rust", attributes: ["check"], container: null, text: "fn a() {}\n" }]);
});

test("fences opened after blockquote or list-item markers are reported as container blocks", () => {
  const text = "> Note:\n>\n> ```rust\n> fn broken( {}\n> ```\n\n> > ```rust,ignore\n> > fn nested( {}\n> > ```\n\n"
    + "- ```rust\n  fn listed( {}\n  ```\n\n1) ~~~rust check\n   fn numbered() {}\n   ~~~\n\n"
    + "> ```rust ignore\n> fn unclosed( {}\n\n```rust check\nfn after() {}\n```\n";
  assert.deepEqual(markdownCodeBlocks(text).map(({ line, info, container, text: body }) => [line, info, container, body]), [
    [3, "rust", "blockquote", "fn broken( {}\n"],
    [7, "rust,ignore", "blockquote", "fn nested( {}\n"],
    [11, "rust", "list item", "fn listed( {}\n"],
    [15, "rust check", "list item", "fn numbered() {}\n"],
    [19, "rust ignore", "blockquote", "fn unclosed( {}\n"],
    [22, "rust check", null, "fn after() {}\n"],
  ]);
  // Inside an ordinary fence, container-prefixed fence lines are content.
  assert.deepEqual(markdownCodeBlocks("````md\n> ```rust\n> fn x() {}\n> ```\n````\n").map((block) => [block.info, block.container]), [["md", null]]);
  // Outside the checked guides, any Rust block not marked fragment is reported, including inside containers.
  assert.deepEqual(unmarkedRustBlocks(text).map((block) => block.line), [3, 7, 11, 15, 19, 22]);
  assert.deepEqual(unmarkedRustBlocks("```rust fragment\nlet x = y?;\n```\n> ```rust fragment\n> z\n> ```\n```bash\nls\n```\n"), []);
});

test("guides reject code blocks inside blockquotes or opened on list-item marker lines", () => {
  const rejects = (text, pattern) => assert.throws(() => extractGuide("docs/guide.md", text, { standalone: true }), pattern);
  rejects("> ```rust\n> fn broken( {}\n> ```\n", /docs\/guide\.md: the code block at line 1 opens inside a blockquote marker line \("rust"\)/);
  rejects("> ```rust ignore\n> fn broken( {}\n> ```\n", /line 1 opens inside a blockquote marker line \("rust ignore"\)/);
  rejects("> ```rust,ignore\n> fn broken( {}\n> ```\n", /line 1 opens inside a blockquote marker line \("rust,ignore"\)/);
  rejects("> ```rust check\n> fn fine() {}\n> ```\n", /opens inside a blockquote marker line/);
  rejects("Intro\n\n> > ```text\n> > note\n> > ```\n", /line 3 opens inside a blockquote marker line/);
  rejects("- ```rust file=notes/src/lib.rs\n  fn listed() {}\n  ```\n", /line 1 opens inside a list item marker line/);
});

test("every Rust block in a guide needs exactly one valid marker", () => {
  const marker = (info) => {
    const [language = "", ...attributes] = info.split(/\s+/).filter(Boolean);
    return guideBlockMarker({ line: 7, info, language, attributes });
  };
  assert.deepEqual(marker("rust check"), { kind: "check" });
  assert.deepEqual(marker("rust fragment"), { kind: "fragment" });
  assert.deepEqual(marker("rust file=example-notes/src/lib.rs"), { kind: "file", crate: "example-notes", path: "src/lib.rs" });
  assert.deepEqual(marker("rust file=team-broker/build.rs"), { kind: "file", crate: "team-broker", path: "build.rs" });
  assert.deepEqual(marker("rust file=a/tests/flow.rs"), { kind: "file", crate: "a", path: "tests/flow.rs" });
  assert.deepEqual(marker("toml file=team-broker/Cargo.toml"), { kind: "file", crate: "team-broker", path: "Cargo.toml" });
  for (const info of ["toml", "bash", "text", "", "json title=x"]) assert.deepEqual(marker(info), { kind: "unchecked" });
  for (const [info, pattern] of [
    ["rust", /line 7: a Rust block needs exactly one marker/],
    ["rust check fragment", /exactly one marker/],
    ["rust check title=x", /exactly one marker/],
    ["rust ignore", /exactly one marker/],
    ["rust,check", /write the info string as `rust <marker>`/],
    ["rust,ignore", /`rust <marker>`/],
    ["Rust check", /`rust <marker>`/],
    ["rs check", /`rust <marker>`/],
    ["rust file=Notes/src/lib.rs", /unsupported marker/],
    ["rust file=notes/lib.rs", /unsupported marker/],
    ["rust file=notes/src/../lib.rs", /unsupported marker/],
    ["rust file=notes/Cargo.toml", /unsupported marker/],
    ["rust file=notes", /unsupported marker/],
    ["toml file=notes/src/lib.rs", /unsupported marker/],
    ["toml check", /only `toml file=<crate>\/Cargo\.toml` marks/],
    ["toml file=notes/Cargo.toml extra", /only `toml file=<crate>\/Cargo\.toml` marks/],
    ["bash check", /only `toml file=<crate>\/Cargo\.toml` marks/],
    ["text fragment", /only `toml file=<crate>\/Cargo\.toml` marks/],
  ]) assert.throws(() => marker(info), pattern, info);
});

test("guide crates join their marked blocks in document order with one manifest naming the crate", () => {
  const guide = [
    "# Guide", fence("toml file=notes/Cargo.toml", exampleManifest("notes")), fence("rust file=notes/src/lib.rs", "pub fn a() {}\n"),
    fence("rust check", "fn standalone() {}\n"), fence("toml", "[providers.notes]\n"), fence("rust fragment", "let x = y?;\n"),
    fence("rust file=notes/src/lib.rs", "pub fn b() {}\n\npub fn c() {}\n"), fence("rust file=notes/tests/flow.rs", "#[test]\nfn flow() {}\n"),
  ].join("\n");
  const { crates, checks, blocks } = extractGuide("docs/guide.md", guide, { standalone: true });
  assert.deepEqual(blocks.map((block) => [block.line, block.kind]), [[2, "file"], [12, "file"], [16, "check"], [20, "unchecked"], [24, "fragment"],
    [28, "file"], [34, "file"]]);
  assert.deepEqual(checks, [{ line: 16, text: "fn standalone() {}\n" }]);
  assert.equal(crates.length, 1);
  assert.equal(crates[0].name, "notes");
  assert.equal(crates[0].manifestLine, 2);
  assert.equal(crates[0].manifest, exampleManifest("notes"));
  assert.deepEqual(crates[0].files, [
    { path: "src/lib.rs", text: "pub fn a() {}\n\npub fn b() {}\n\npub fn c() {}\n", origins: [{ guideLine: 13, fileLine: 1 }, { guideLine: 29, fileLine: 3 }] },
    { path: "tests/flow.rs", text: "#[test]\nfn flow() {}\n", origins: [{ guideLine: 35, fileLine: 1 }] },
  ]);
  const rejects = (text, pattern, options = { standalone: true }) => assert.throws(() => extractGuide("docs/guide.md", text, options), pattern);
  rejects(fence("rust check", "fn a() {}\n"), /docs\/guide\.md: the Rust block at line 1 is marked check, but only docs\/provider-sdk\.md compiles/, {});
  rejects(fence("rust", "fn a() {}\n"), /docs\/guide\.md: the `rust` block at line 1: a Rust block needs exactly one marker/);
  rejects(fence("rust file=notes/src/lib.rs", "fn a() {}\n"), /example crate notes has no `toml file=notes\/Cargo\.toml` block/);
  rejects(fence("toml file=notes/Cargo.toml", exampleManifest("notes")), /example crate notes has no src\/lib\.rs or src\/main\.rs block/);
  rejects(`${fence("toml file=notes/Cargo.toml", exampleManifest("other"))}${fence("rust file=notes/src/lib.rs", "")}`,
    /notes\/Cargo\.toml at line 1 must declare package notes; found other/);
  rejects(`${fence("toml file=notes/Cargo.toml", exampleManifest("notes"))}${fence("toml file=notes/Cargo.toml", exampleManifest("notes"))}`,
    /line 10 defines notes\/Cargo\.toml again; line 1 defines it/);
  assert.equal(manifestPackageField(`[package]\nname = "a" # comment\nedition = "2024"\n[dependencies]\nname = "b"\n`, "name"), "a");
  assert.equal(manifestPackageField(`[dependencies]\nname = "b"\n`, "name"), null);
});

test("standalone blocks compile as one module each in a generated SDK-only crate", () => {
  const crate = snippetCrate("docs/provider-sdk.md", [{ line: 42, text: "fn a() {}\n" }, { line: 77, text: "fn b() {}\n" }]);
  assert.equal(crate.name, GUIDE_SNIPPET_PACKAGE);
  assert.equal(manifestPackageField(crate.manifest, "name"), GUIDE_SNIPPET_PACKAGE);
  assert.equal(manifestPackageField(crate.manifest, "edition"), "2024");
  assert.deepEqual(manifestDependencies(crate.manifest).entries.map((entry) => [entry.key, entry.spec]), [[SDK_PACKAGE, { workspace: true }]]);
  assert.deepEqual(crate.files.map((file) => [file.path, file.origins]), [["src/lib.rs", []], ["src/line_42.rs", [{ guideLine: 43, fileLine: 1 }]],
    ["src/line_77.rs", [{ guideLine: 78, fileLine: 1 }]]]);
  assert.match(crate.files[0].text, /^#!\[allow\(dead_code\)\]$/m);
  assert.match(crate.files[0].text, /^\/\/\/ docs\/provider-sdk\.md, the block whose fence opens at line 42\.\nmod line_42;\n/m);
  assert.equal(crate.files[2].text, "fn b() {}\n");
});

test("guide manifest placeholders are staged like the fixture's sentinel pins", () => {
  const manifest = `${exampleManifest("example-notes")}\n[dev-dependencies]\n`
    + `${SDK_PACKAGE} = { git = "${CANONICAL_UPSTREAM_URL}", rev = "<full 40-character commit>", features = ["test-support"] }\n`;
  const { text, rewrites } = rewriteStagedManifest(guideManifestPins(manifest), [upstream]);
  assert.equal(text, manifest.replaceAll(`"${CANONICAL_UPSTREAM_URL}", rev = "<full 40-character commit>"`, `"${upstreamUrl}", rev = "${commit}"`));
  assert.deepEqual(rewrites.map((rewrite) => rewrite.table), ["dependencies", "dev-dependencies"]);
  const assembly = `[dependencies]\nagent-access-broker-host = { git = "${CANONICAL_UPSTREAM_URL}", rev = "<full upstream commit>" }\n`
    + `example-notes = { git = "${GUIDE_PROVIDER_URL}", rev = "<full provider commit>" }\n`;
  const notes = { canonical: GUIDE_PROVIDER_URL, url: providerUrl, rev: providerCommit, packages: new Set(["example-notes"]) };
  assert.deepEqual(rewriteStagedManifest(guideManifestPins(assembly), [notes, upstream]).rewrites.map((rewrite) => [rewrite.package, rewrite.staged.git]),
    [["agent-access-broker-host", upstreamUrl], ["example-notes", providerUrl]]);
  assert.throws(() => rewriteStagedManifest(guideManifestPins(`[dependencies]\n${SDK_PACKAGE} = ${pin(CANONICAL_UPSTREAM_URL, commit)}\n`), [upstream]),
    /must pin the sentinel rev/);
  assert.throws(() => rewriteStagedManifest(guideManifestPins(`[dependencies]\nexample-notes = { git = "${CANONICAL_PROVIDER_URL}", rev = "<x>" }\n`),
    [notes, upstream]), /must use exactly https:\/\/git\.example\.com\/notes-team/);
  assert.throws(() => rewriteStagedManifest(guideManifestPins(`[dependencies]\nexample-notes = { path = "../notes" }\n`), [notes, upstream]),
    /must not use path/);
});

test("the assembly guide's shared files must equal the fixture's with the stated renames", () => {
  const shared = [{ path: "build.rs", renames: [["FIXTURE_", "GUIDE_"]] }, { path: "src/main.rs", renames: [["fixture_crate", "guide_crate"]] }];
  const fixtureFiles = new Map([["build.rs", "emit(\"FIXTURE_REVISION\");\nemit(\"FIXTURE_VERSION\");\n"], ["src/main.rs", "use fixture_crate::run;\nfn main() { run() }\n"]]);
  const guideMain = "use guide_crate::run;\nfn main() { run() }\n";
  const { files, checks } = sharedAssemblyFiles({ guideFiles: new Map([["src/lib.rs", "pub fn run() {}\n"], ["src/main.rs", guideMain]]), fixtureFiles, shared });
  assert.deepEqual([...files], [["src/lib.rs", "pub fn run() {}\n"], ["src/main.rs", guideMain], ["build.rs", "emit(\"GUIDE_REVISION\");\nemit(\"GUIDE_VERSION\");\n"]]);
  assert.deepEqual(checks.map((check) => [check.path, check.staged]), [["build.rs", "fixture file with the renames"],
    ["src/main.rs", "guide block, equal to the fixture file with the renames"]]);
  assert.throws(() => sharedAssemblyFiles({ guideFiles: new Map([["src/main.rs", guideMain.replace("run() }", "run(); }")]]), fixtureFiles, shared }),
    /shows a src\/main\.rs that differs from the fixture's .*first at its line 2: "fn main\(\) \{ run\(\); \}" instead of "fn main\(\) \{ run\(\) \}"/);
  assert.throws(() => sharedAssemblyFiles({ guideFiles: new Map([["src/main.rs", `${guideMain}// more\n`]]), fixtureFiles, shared }),
    /first at its line 3: "\/\/ more" instead of ""/);
  assert.throws(() => sharedAssemblyFiles({ guideFiles: new Map(), fixtureFiles: new Map([...fixtureFiles, ["build.rs", "emit();\n"]]), shared }),
    /fixture's build\.rs no longer contains "FIXTURE_"; update what docs\/downstream-assembly\.md states/);
  assert.throws(() => sharedAssemblyFiles({ guideFiles: new Map(), fixtureFiles: new Map([["build.rs", "FIXTURE_"]]), shared }),
    /fixture assembly template has no src\/main\.rs/);
});

const sharedFixtureFiles = () => new Map(ASSEMBLY_GUIDE_SHARED_FILES.map(({ path }) => [path, read(`tests/downstream-consumer/assembly-repo/${path}`)]));

test("the checked-in guides yield the staged example crates and share files with the fixture as they state", () => {
  const workspace = new Set(parseLockfile(read("Cargo.lock")).packages.filter((entry) => entry.source === null).map((entry) => entry.name));
  const reservedNames = new Set([...workspace, ASSEMBLY_PACKAGE]);
  const examples = guideExamples({ providerGuide: read(PROVIDER_GUIDE), assemblyGuide: read(ASSEMBLY_GUIDE), fixtureFiles: sharedFixtureFiles(), reservedNames });
  assert.deepEqual(examples.destinations.map(({ crate, repository, directory }) => [crate.name, repository, directory]), [
    ["example-notes", "provider", "crates/example-notes"], [GUIDE_SNIPPET_PACKAGE, "provider", `crates/${GUIDE_SNIPPET_PACKAGE}`], ["team-broker", "guide-assembly", "."]]);
  const rust = examples.inventory.guides.flatMap(({ path, blocks }) => blocks.filter((block) => /^rust\b/.test(block.info)).map((block) => [path, block.kind]));
  assert.ok(rust.every(([, kind]) => ["check", "file", "fragment"].includes(kind)));
  assert.ok(rust.filter(([path, kind]) => path === PROVIDER_GUIDE && kind === "check").length >= 1);
  assert.deepEqual(examples.assemblyCrate.files.map((file) => [file.path, file.fixture ?? "guide"]),
    [["src/lib.rs", "guide"], ["src/main.rs", "guide"], ["build.rs", "tests/downstream-consumer/assembly-repo/build.rs"]]);
  assert.match(examples.assemblyCrate.files[2].text, /cargo:rustc-env=TEAM_BROKER_\{prefix\}_REVISION/);
  assert.match(examples.assemblyCrate.files[2].text, /\("NOTES", "example-notes"\)/);
  // Both guide manifests stage against the fixture's sources.
  const notes = { canonical: GUIDE_PROVIDER_URL, url: providerUrl, rev: providerCommit, packages: new Set(["example-notes", GUIDE_SNIPPET_PACKAGE]) };
  for (const crate of [...examples.providerCrates, examples.assemblyCrate]) {
    const staged = rewriteStagedManifest(guideManifestPins(crate.manifest), [notes, { ...upstream, packages: workspace }]);
    assert.ok(!staged.text.includes(CANONICAL_UPSTREAM_URL) && !staged.text.includes(GUIDE_PROVIDER_URL), crate.name);
    assert.equal(manifestPackageField(crate.manifest, "edition"), "2024", crate.name);
  }
  assert.throws(() => guideExamples({ providerGuide: read(PROVIDER_GUIDE), assemblyGuide: read(ASSEMBLY_GUIDE), fixtureFiles: sharedFixtureFiles(),
    reservedNames: new Set(["team-broker"]) }), /must not reuse an upstream, fixture or other guide crate name: team-broker/);
  assert.throws(() => guideExamples({ providerGuide: read(PROVIDER_GUIDE), assemblyGuide: "", fixtureFiles: sharedFixtureFiles(), reservedNames }),
    /must mark exactly one example assembly crate; found none/);
  assert.throws(() => guideExamples({ providerGuide: "", assemblyGuide: read(ASSEMBLY_GUIDE), fixtureFiles: sharedFixtureFiles(), reservedNames }),
    /docs\/provider-sdk\.md marks no example crate/);
});

test("Rust blocks outside the checked guides are marked as fragments, so none is silently unchecked", () => {
  const files = execFileSync("git", ["ls-files", "-z", "--", "*.md"], { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean);
  assert.ok(files.includes(PROVIDER_GUIDE) && files.includes(ASSEMBLY_GUIDE));
  const unchecked = files.filter((file) => ![PROVIDER_GUIDE, ASSEMBLY_GUIDE].includes(file))
    .flatMap((file) => unmarkedRustBlocks(read(file)).map((block) => `${file}:${block.line} (${block.info})`));
  assert.deepEqual(unchecked, []);
});

test("dep-info prerequisites are read with their escapes, ignoring comments and targets", () => {
  const files = dependencyInfoFiles("/target/debug/deps/notes-1.d: crates/notes/src/lib.rs crates/notes/src/my\\ file.rs\n\n"
    + "/target/debug/deps/libnotes-1.rlib: crates/notes/src/lib.rs\n\ncrates/notes/src/lib.rs:\n# env-dep:NOTES_REVISION=abc\n");
  assert.deepEqual([...files], ["crates/notes/src/lib.rs", "crates/notes/src/my file.rs"]);
});

test("real cargo test: only files a target's module tree reaches count as compiled", (t) => {
  const directory = temporary(t);
  const write = (file, contents) => {
    mkdirSync(join(directory, file, ".."), { recursive: true });
    writeFileSync(join(directory, file), contents);
  };
  write("Cargo.toml", '[workspace]\nmembers = ["crates/*"]\nresolver = "3"\n\n[profile.dev]\ndebug = false\nincremental = false\n');
  write("crates/notes/Cargo.toml", '[package]\nname = "notes"\nversion = "0.1.0"\nedition = "2024"\n');
  write("crates/notes/src/lib.rs", "mod nested;\npub fn a() {}\n");
  write("crates/notes/src/nested.rs", "#[cfg(test)]\nmod inner;\n");
  write("crates/notes/src/nested/inner.rs", "#[test]\nfn inner() {}\n");
  write("crates/notes/src/main.rs", "fn main() {}\n");
  write("crates/notes/build.rs", "fn main() {}\n");
  write("crates/notes/tests/flow.rs", "#[test]\nfn flow() {}\n");
  // Broken code nothing declares: Cargo never compiles it, so the build passes.
  write("crates/notes/src/orphan.rs", "fn broken( {}\n");
  const toolchain = inspectLocalToolchain(root, { env: sanitizedEnvironment(process.env).env });
  const env = { ...sanitizedEnvironment(process.env).env, CARGO_HOME: join(directory, "cargo-home"), RUSTC: toolchain.rustcPath };
  execFileSync(toolchain.cargoPath, ["test", "--offline", "--quiet"], { cwd: directory, env, stdio: ["ignore", "pipe", "pipe"] });
  const compiled = compiledSourceFiles(join(directory, "target"), directory);
  const source = (path) => join(directory, "crates", "notes", path);
  for (const path of ["src/lib.rs", "src/nested.rs", "src/nested/inner.rs", "src/main.rs", "build.rs", "tests/flow.rs"]) {
    assert.ok(compiled.has(source(path)), path);
  }
  assert.ok(!compiled.has(source("src/orphan.rs")));
  assert.equal(compiledSourceFiles(join(directory, "missing-target"), directory).size, 0);
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
  const guideLock = [
    { name: "team-broker", version: "1.4.0" },
    { name: "agent-access-broker-host", version: "0.1.0", source: upstreamSource },
    { name: "example-notes", version: "0.1.0", source: providerSource },
    { name: SDK_PACKAGE, version: "0.1.0", source: upstreamSource },
  ];
  const providerPackages = new Set([PROVIDER_PACKAGE, "example-notes"]);
  const review = (providerPackagesLock, assemblyPackages, guidePackages = guideLock) => reviewLockfiles({ candidate: parseLockfile(candidateLock),
    staged: [{ repository: "provider", lock: parseLockfile(lockText(providerPackagesLock)), members: [PROVIDER_PACKAGE] },
      { repository: "assembly", lock: parseLockfile(lockText(assemblyPackages)), members: [ASSEMBLY_PACKAGE] },
      { repository: "guide-assembly", lock: parseLockfile(lockText(guidePackages)), members: ["team-broker"] }],
    upstreamSource, providerSource, providerPackages });
  const passing = review(providerLock, assemblyLock);
  assert.deepEqual(passing.errors, []);
  assert.deepEqual(passing.sdkPackageIds, [`${SDK_PACKAGE} 0.1.0 ${upstreamSource}`]);
  assert.deepEqual(passing.summary.map((entry) => [entry.repository, entry.workspace, entry.upstream, entry.provider, entry.thirdParty]),
    [["provider", 1, 1, 0, 1], ["assembly", 1, 2, 1, 1], ["guide-assembly", 1, 2, 1, 0]]);
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
    [review(providerLock, assemblyLock, withEntry(guideLock, 2, { name: "other-notes" })), /guide-assembly: other-notes .* is not a provider repository package/],
    [review(providerLock, assemblyLock, withEntry(guideLock, 3, { source: gitSourceId(upstreamUrl, providerCommit) })), /exactly one agent-access-provider package ID/],
  ];
  for (const [result, pattern] of failures) assert.ok(result.errors.some((error) => pattern.test(error)), `${pattern}: ${result.errors.join("; ")}`);
});

test("graph checks reject resolved release test support and forbidden provider edges", () => {
  const tree = "downstream-broker v0.3.0 (/stage/assembly)\t\n"
    + "agent-access-broker-host v0.1.0 (file:///stage/upstream?rev=abc#abc)\tdefault\n"
    + "agent-access-provider v0.1.0 (file:///stage/upstream?rev=abc#abc)\ttest-support (*)\n"
    + "tokio v1.48.0\tdefault,macros,test-support-extra\n";
  assert.deepEqual(assemblyFeatureViolations(tree),
    ["agent-access-provider 0.1.0 (file:///stage/upstream?rev=abc#abc) enables test-support"]);
  assert.deepEqual(assemblyFeatureViolations(tree.replace("\ttest-support (*)", "\tdefault")), []);
  assert.throws(() => assemblyFeatureViolations("tokio v1.48.0\tdefault\n"), /omits the assembly package downstream-broker/);
  assert.deepEqual(assemblyFeatureTreeArgs("x86_64-unknown-linux-gnu"), ["tree", "--locked", "--offline", "--target", "x86_64-unknown-linux-gnu",
    "-p", ASSEMBLY_PACKAGE, "-e", "normal,build", "--prefix", "none", "--format", "{p}\t{f}"]);
  const role = (name, value) => ({ name, version: "0.1.0", metadata: value ? { "agent-access": { role: value } } : null });
  assert.deepEqual(providerBoundaryViolations({ packages: [role(PROVIDER_PACKAGE, "reference"), role(SDK_PACKAGE, "sdk"), role("serde")] }), []);
  assert.deepEqual(providerBoundaryViolations({ packages: [role("agent-access-core", "core"), role("agent-access-broker-host", "host"),
    role("agent-access-mcp-upstream", "adapter")] }).length, 3);
});

const upstreamCommit = "c".repeat(40);
const expectedStatus = () => expectedAssemblyStatus({
  assembly: { name: ASSEMBLY_PACKAGE, version: "0.3.0", qualification: FIXTURE_QUALIFICATION, revision: commit },
  host: { version: "0.2.0", revision: upstreamCommit },
  sdk: { version: "0.2.0", revision: upstreamCommit },
  modules: [
    { crate: PROVIDER_PACKAGE, version: "0.7.0", roles: [{ role: "native", id: "conformance" }], revision: providerCommit },
    { crate: "agent-access-cloudbees-ci", version: "0.2.0", roles: [{ role: "native", id: "cloudbees_ci" }], revision: upstreamCommit },
  ],
});

test("the expected status orders modules canonically and carries the recomputed fingerprint", () => {
  const expected = expectedStatus();
  assert.deepEqual(expected.modules.map((module) => module.crate), ["agent-access-cloudbees-ci", PROVIDER_PACKAGE]);
  assert.deepEqual(expected.sdk, { crate: SDK_PACKAGE, version: "0.2.0", source: { revision: upstreamCommit, provenance: "evidence" } });
  assert.match(expected.inventoryFingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.equal(expected.inventoryFingerprint, inventoryFingerprint(expected));
  // The assembly fields are outside the fingerprint; every inventory field is inside it.
  const relabelled = structuredClone(expected);
  relabelled.assembly.qualification = "unqualified";
  assert.equal(inventoryFingerprint(relabelled), expected.inventoryFingerprint);
  for (const change of [
    (status) => { status.host.source.revision = "d".repeat(40); },
    (status) => { status.sdk.version = "0.2.1"; },
    (status) => { status.modules[1].source = { revision: null, provenance: "unavailable" }; },
    (status) => { status.modules[0].roles.push({ role: "oauth", id: "example" }); },
    (status) => { status.modules.pop(); },
  ]) {
    const changed = structuredClone(expected);
    change(changed);
    assert.notEqual(inventoryFingerprint(changed), expected.inventoryFingerprint);
  }
});

// A status the Broker host reported for a staged assembly, so the recomputed
// fingerprint is checked against the host's own encoding.
const HOST_REPORTED_INVENTORY = {
  "host": {
    "crate": "agent-access-broker-host",
    "version": "0.1.0",
    "source": {
      "revision": "e4269217a450b27776e9bc13f9d691e3d68bf15d",
      "provenance": "evidence"
    }
  },
  "sdk": {
    "crate": "agent-access-provider",
    "version": "0.1.0",
    "source": {
      "revision": "e4269217a450b27776e9bc13f9d691e3d68bf15d",
      "provenance": "evidence"
    }
  },
  "modules": [
    {
      "crate": "agent-access-cloudbees-ci",
      "version": "0.1.0",
      "roles": [
        {
          "role": "native",
          "id": "cloudbees_ci"
        }
      ],
      "source": {
        "revision": "e4269217a450b27776e9bc13f9d691e3d68bf15d",
        "provenance": "evidence"
      }
    },
    {
      "crate": "agent-access-conformance",
      "version": "0.7.0",
      "roles": [
        {
          "role": "native",
          "id": "conformance"
        }
      ],
      "source": {
        "revision": "ef7d15d5b78d0d98e2d4c2ea39fe748980c15823",
        "provenance": "evidence"
      }
    }
  ],
  "inventoryFingerprint": "sha256:d1855abfb91ea4be2ed59390310ef5a9bf0f546237c3b0ea27e448d75f00aa1d"
};

test("the recomputed inventory fingerprint matches the host's", () => {
  assert.equal(inventoryFingerprint(HOST_REPORTED_INVENTORY), HOST_REPORTED_INVENTORY.inventoryFingerprint);
});

test("the status must match the assembly's identity, locked sources and fingerprint exactly", () => {
  const reported = { ...expectedStatus(), catalogVersion: "agent-access.catalog.v2", sendSchemaVersion: "agent-access.send.v1" };
  assertAssemblyStatus(reported, expectedStatus());
  for (const corrupt of [
    (status) => { status.assembly.qualification = "unqualified"; },
    (status) => { status.assembly.source = { revision: null, provenance: "unavailable" }; },
    (status) => { status.host.source.provenance = "declared"; },
    (status) => { status.modules[1].source.revision = upstreamCommit; },
    (status) => { status.modules.reverse(); },
    (status) => { status.inventoryFingerprint = `sha256:${"0".repeat(64)}`; },
    (status) => { delete status.catalogVersion; },
    (status) => { status.brokerVersion = "0.3.0"; },
  ]) {
    const status = structuredClone(reported);
    corrupt(status);
    assert.throws(() => assertAssemblyStatus(status, expectedStatus()), /assembly's identity/);
  }
  assert.throws(() => assertAssemblyStatus(null, expectedStatus()), /assembly's identity/);
  const status = expectedStatus();
  const starting = { event: "broker_starting", assemblyName: ASSEMBLY_PACKAGE, assemblyVersion: "0.3.0", assemblyRevision: commit,
    assemblyProvenance: "evidence", qualification: FIXTURE_QUALIFICATION, inventoryFingerprint: status.inventoryFingerprint };
  const log = (event) => `not json\n${JSON.stringify({ event: "broker_listening" })}\n${JSON.stringify(event)}\n`;
  assertStartingEvent(log(starting), status);
  assert.throws(() => assertStartingEvent(log({ ...starting, inventoryFingerprint: "sha256:other" }), status), /broker_starting/);
  assert.throws(() => assertStartingEvent(log({ ...starting, qualification: "unqualified" }), status), /broker_starting/);
  assert.throws(() => assertStartingEvent(`${log(starting)}${JSON.stringify(starting)}\n`, status), /broker_starting/);
});

test("environment sanitization keeps only build parallelism of the Cargo settings", () => {
  const { env, removed } = sanitizedEnvironment({ PATH: "/bin", HOME: "/home/x", CARGO_HOME: "/c", CARGO_TARGET_DIR: "/t", CARGO_PROFILE_DEV_DEBUG: "0",
    RUSTFLAGS: "-C x", RUSTC_WRAPPER: "sccache", RUSTUP_TOOLCHAIN: "nightly", CC: "clang", AGENT_ACCESS_BROKER_CONFIG: "/x", RUSTUP_HOME: "/r",
    DOWNSTREAM_BROKER_QUALIFICATION: "release", TEAM_BROKER_REVISION: "f".repeat(40), CARGO_BUILD_JOBS: "4" });
  assert.deepEqual(env, { PATH: "/bin", HOME: "/home/x", RUSTUP_HOME: "/r", CARGO_BUILD_JOBS: "4" });
  assert.deepEqual(removed, ["AGENT_ACCESS_BROKER_CONFIG", "CARGO_HOME", "CARGO_PROFILE_DEV_DEBUG", "CARGO_TARGET_DIR", "CC",
    "DOWNSTREAM_BROKER_QUALIFICATION", "RUSTC_WRAPPER", "RUSTFLAGS", "RUSTUP_TOOLCHAIN", "TEAM_BROKER_REVISION"]);
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
    env: sanitizedEnvironment(process.env).env, expectedStatus: {} });
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

// A stand-in assembled broker: `config` subcommands succeed as the real
// validation does for these configurations, and `serve` runs `serve`, a
// script body with `args` in scope.
const standInBroker = (directory, serve) => {
  const broker = join(directory, "stand-in-broker.mjs");
  writeFileSync(broker, `#!/usr/bin/env node
import { readFileSync } from "node:fs";
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
${serve}
`);
  chmodSync(broker, 0o755);
  return broker;
};

const acceptanceRun = (directory, broker, env = sanitizedEnvironment(process.env).env) => {
  const supervisor = new ProcessSupervisor({ graceMs: 2_000 });
  const acceptance = runProcessAcceptance({ supervisor, binary: broker, cli: join(directory, "unused-cli"),
    run: join(directory, "run"), evidence: join(directory, "evidence"), env, expectedStatus: {} });
  return { supervisor, acceptance };
};

test("broker acceptance binds port 0 and reaches the address broker_listening reports", posixOnly, async (t) => {
  const directory = temporary(t);
  const broker = standInBroker(directory, `
if (args[4] !== "127.0.0.1:0") process.exit(9);
const server = createServer((request, response) => {
  response.writeHead(request.url === "/v1/readyz" ? 200 : 503);
  response.end();
});
server.listen(0, "127.0.0.1", () => {
  process.stdout.write(JSON.stringify({ event: "broker_starting", publicListen: args[4] }) + "\\n");
  process.stdout.write(JSON.stringify({ event: "broker_listening", listener: "public", address: "127.0.0.1:" + server.address().port }) + "\\n");
});
process.on("SIGTERM", () => process.exit(0));
`);
  const { supervisor, acceptance } = acceptanceRun(directory, broker);
  try {
    // Readiness passed at the reported address; the next check fails there.
    await assert.rejects(acceptance, /Process acceptance failed: healthz \(\{"status":503\}\)/);
  } finally {
    await supervisor.stopAll();
  }
});

test("broker acceptance reads the listening address under an inherited warning-only filter", posixOnly, async (t) => {
  const directory = temporary(t);
  // Like the Broker, a warning-only RUST_LOG hides the INFO broker_listening event.
  const broker = standInBroker(directory, `
import { writeFileSync } from "node:fs";
writeFileSync("broker-rust-log", process.env.RUST_LOG ?? "");
const server = createServer((request, response) => {
  response.writeHead(request.url === "/v1/readyz" ? 200 : 503);
  response.end();
});
server.listen(0, "127.0.0.1", () => {
  if (process.env.RUST_LOG !== "warn") {
    process.stdout.write(JSON.stringify({ event: "broker_listening", listener: "public", address: "127.0.0.1:" + server.address().port }) + "\\n");
  }
});
process.on("SIGTERM", () => process.exit(0));
`);
  const env = { ...sanitizedEnvironment(process.env).env, RUST_LOG: "warn" };
  const { supervisor, acceptance } = acceptanceRun(directory, broker, env);
  try {
    await assert.rejects(acceptance, /Process acceptance failed: healthz \(\{"status":503\}\)/);
    assert.equal(readFileSync(join(directory, "run", "broker-rust-log"), "utf8"), BROKER_LOG_FILTER);
  } finally {
    await supervisor.stopAll();
  }
});

test("a broker that exits before reporting its listener fails acceptance at once", posixOnly, async (t) => {
  const directory = temporary(t);
  const broker = standInBroker(directory, `
process.stderr.write(JSON.stringify({ event: "broker_start_failed", error: "Address already in use (os error 98)" }) + "\\n");
process.exit(1);
`);
  const { supervisor, acceptance } = acceptanceRun(directory, broker);
  const started = Date.now();
  try {
    await assert.rejects(acceptance, /The assembled broker exited before readiness with 1/);
    assert.ok(Date.now() - started < 30_000, "early exit must not wait for the readiness deadline");
  } finally {
    await supervisor.stopAll();
  }
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

// A minimal real assembly: the host stand-in's test-support feature reaches the
// assembly either through the assembly's own default features or only
// through a dev-dependency, as in the fixture template.
function assemblyFeatureFixture(t, { rootDefault }) {
  const directory = temporary(t);
  const write = (file, contents) => {
    mkdirSync(join(directory, file, ".."), { recursive: true });
    writeFileSync(join(directory, file), contents);
  };
  const host = 'agent-access-broker-host = { path = "host" }';
  write("Cargo.toml", `[package]\nname = "${ASSEMBLY_PACKAGE}"\nversion = "0.3.0"\nedition = "2024"\n\n[dependencies]\n${host}\n\n`
    + '[dev-dependencies]\nagent-access-broker-host = { path = "host", features = ["test-support"] }\n'
    + (rootDefault ? '\n[features]\ndefault = ["agent-access-broker-host/test-support"]\n' : "") + "\n[workspace]\n");
  write("src/lib.rs", "");
  write("host/Cargo.toml", '[package]\nname = "agent-access-broker-host"\nversion = "0.1.0"\nedition = "2024"\n\n[features]\ntest-support = []\n');
  write("host/src/lib.rs", "");
  const toolchain = inspectLocalToolchain(root, { env: sanitizedEnvironment(process.env).env });
  const env = { ...sanitizedEnvironment(process.env).env, CARGO_HOME: join(directory, "cargo-home"), RUSTC: toolchain.rustcPath };
  const cargo = (args) => execFileSync(toolchain.cargoPath, args, { cwd: directory, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  cargo(["generate-lockfile", "--offline"]);
  return cargo(assemblyFeatureTreeArgs(toolchain.host));
}

test("real cargo tree: test support enabled by the assembly's default features is rejected", (t) => {
  const violations = assemblyFeatureViolations(assemblyFeatureFixture(t, { rootDefault: true }));
  assert.equal(violations.length, 1, violations.join("; "));
  assert.match(violations[0], /^agent-access-broker-host 0\.1\.0 \(.*\/host\) enables test-support$/);
});

test("real cargo tree: test support enabled only through a dev-dependency stays allowed", (t) => {
  const output = assemblyFeatureFixture(t, { rootDefault: false });
  assert.deepEqual(assemblyFeatureViolations(output), []);
  assert.match(output, /^agent-access-broker-host v0\.1\.0 \(.*\/host\)\t/m);
});
