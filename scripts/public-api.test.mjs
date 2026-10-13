import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  CARGO_PUBLIC_API_VERSION, PUBLIC_API_TOOLCHAIN, PublicApiPrerequisiteError, RUSTUP_HOME_VARIABLE,
  SELECTION_ENTRY_POINTS, compareInventories, compatibleLine, dependencyLines, exposureClosure,
  formatComparison, inspectPublicApiToolchain, inventorySurfaces, parsePublicApiArguments,
  parseResolvedPackages, pruneToEntryPoints, publicApiEnvironment, reachableIds, referencedIds,
  renderInventory, rustdocArguments, synthesizeExposure, treeArguments, visibleNames,
} from "./public-api.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));

// Minimal rustdoc JSON (format 60) documents.
const item = (id, name, inner) => ({ id, crate_id: 0, name, span: null, visibility: "public", docs: null,
  links: {}, attrs: [], deprecation: null, inner });
const module = (id, name, items) => item(id, name, { module: { is_crate: id === 0, items, is_stripped: false } });
const struct = (id, name, impls = []) => item(id, name, { struct: { kind: "unit", generics: { params: [], where_predicates: [] }, impls } });
const typePath = (name, id) => ({ resolved_path: { path: name, id, args: null } });
const fn = (id, name, output) => item(id, name, { function: { sig: { inputs: [], output, is_c_variadic: false } } });
const use = (id, name, target, glob = false) => item(id, null, { use: { source: name, name, id: target, is_glob: glob } });
const impl = (id, items, { trait = null, blanket = null, forType } = {}) => item(id, null, { impl: {
  is_unsafe: false, generics: { params: [], where_predicates: [] }, provided_trait_methods: [], trait,
  for: forType, items, is_negative: false, is_synthetic: false, blanket_impl: blanket } });
const crate = (items, paths, externalCrates = {}) => ({ root: 0, format_version: 60,
  index: Object.fromEntries(items.map((entry) => [String(entry.id), entry])), paths,
  external_crates: Object.fromEntries(Object.entries(externalCrates).map(([id, name]) => [id, { name, html_root_url: null }])) });

// `alpha` exports ENTRY (an SDK type), registration() (a core type), and a
// glob-exported Hidden with a Clone impl and a blanket impl naming `third`.
const alpha = () => crate([
  module(0, "alpha", [1, 2, 3, 4]),
  item(1, "ENTRY", { static: { type: typePath("Registration", 100), is_mutable: false, is_unsafe: false, expr: "" } }),
  fn(2, "registration", typePath("Exposed", 101)),
  use(3, "hidden", 5, true),
  use(4, "Renamed", 6),
  module(5, "hidden", [6]),
  struct(6, "Hidden", [7, 8]),
  impl(7, [9], { trait: { path: "Clone", id: 102, args: null }, forType: typePath("Hidden", 6) }),
  impl(8, [10], { trait: { path: "Third", id: 103, args: null }, blanket: { generic: "T" }, forType: { generic: "T" } }),
  fn(9, "clone", typePath("Hidden", 6)),
  fn(10, "third", null),
], {
  1: { crate_id: 0, path: ["alpha", "ENTRY"], kind: "static" },
  2: { crate_id: 0, path: ["alpha", "registration"], kind: "function" },
  6: { crate_id: 0, path: ["alpha", "hidden", "Hidden"], kind: "struct" },
  100: { crate_id: 1, path: ["sdk_lib", "backend", "Registration"], kind: "struct" },
  101: { crate_id: 2, path: ["core_lib", "things", "Exposed"], kind: "struct" },
  102: { crate_id: 3, path: ["core", "clone", "Clone"], kind: "trait" },
  103: { crate_id: 4, path: ["third", "Third"], kind: "trait" },
}, { 1: "sdk_lib", 2: "core_lib", 3: "core", 4: "third" });

const sdk = () => crate([
  module(0, "sdk_lib", [1]),
  use(1, "backend", 2, true),
  module(2, "backend", [3]),
  struct(3, "Registration"),
], {
  2: { crate_id: 0, path: ["sdk_lib", "backend"], kind: "module" },
  3: { crate_id: 0, path: ["sdk_lib", "backend", "Registration"], kind: "struct" },
});

// Core's Exposed has a method returning Inner and taking `other::Other`.
const core = () => crate([
  module(0, "core_lib", []),
  struct(10, "Exposed", [11]),
  impl(11, [12], { forType: typePath("Exposed", 10) }),
  item(12, "next", { function: { sig: { inputs: [["value", typePath("Other", 200)]], output: typePath("Inner", 13), is_c_variadic: false } } }),
  struct(13, "Inner"),
], {
  10: { crate_id: 0, path: ["core_lib", "things", "Exposed"], kind: "struct" },
  13: { crate_id: 0, path: ["core_lib", "things", "Inner"], kind: "struct" },
  200: { crate_id: 1, path: ["other", "Other"], kind: "struct" },
}, { 1: "other" });

const workspace = new Map([["alpha", { package: "alpha" }], ["sdk_lib", { package: "sdk" }], ["core_lib", { package: "core-crate" }]]);
const resolvedFor = () => parseResolvedPackages([
  "alpha v0.1.0 (/checkout/crates/alpha)\talpha\t",
  "sdk v0.1.0 (/checkout/crates/sdk)\tsdk_lib\t",
  "core-crate v0.1.0 (/checkout/crates/core)\tcore_lib\t",
  "sdk v0.1.0 (/checkout/crates/sdk)\tsdk_lib\t (*)",
  "other v1.4.2\tother\tdefault,std",
  "third v0.12.28\tthird\t",
].join("\n"));

test("arguments select check or update mode", () => {
  assert.deepEqual(parsePublicApiArguments(["check"]), { mode: "check" });
  assert.deepEqual(parsePublicApiArguments(["update"]), { mode: "update" });
  for (const args of [[], ["diff"], ["check", "update"], ["--check"]]) {
    assert.throws(() => parsePublicApiArguments(args), /Usage: node scripts\/public-api.mjs check\|update/);
  }
});

const metadataPackage = (name, role, { features = {}, library = name.replaceAll("-", "_"), dependencies = [] } = {}) => ({
  id: `path+file:///checkout/${name}#0.1.0`, name, features, dependencies,
  metadata: { "agent-access": { role } },
  targets: library ? [{ name: library, kind: ["lib"] }] : [{ name, kind: ["bin"] }],
});
const metadata = (entries) => ({ packages: entries, workspace_members: entries.map((entry) => entry.id) });
const fixtureMetadata = () => metadata([
  metadataPackage("x-provider", "sdk", { features: { "test-support": [] } }),
  metadataPackage("x-host", "host"),
  metadataPackage("x-broker", "assembly", { dependencies: [
    { name: "x-host", kind: null }, { name: "x-native", kind: null }, { name: "x-adapter", kind: null },
    { name: "x-core", kind: null }, { name: "x-reference", kind: "dev" }, { name: "x-extra", kind: "dev" }] }),
  metadataPackage("x-native", "native"),
  metadataPackage("x-extra", "native"),
  metadataPackage("x-adapter", "adapter"),
  metadataPackage("x-core", "core", { features: { "test-support": [] } }),
  metadataPackage("x-reference", "reference"),
  metadataPackage("x", "cli", { library: null }),
]);
const fixtureEntryPoints = { "x-native": ["x_native::NATIVE"], "x-adapter": ["x_adapter::registration"] };

test("surfaces cover the SDK and host with and without test support, the assembly and linked selections", () => {
  const surfaces = inventorySurfaces(fixtureMetadata(), fixtureEntryPoints);
  assert.deepEqual(surfaces.map((surface) => [surface.file, surface.features, surface.entryPoints]), [
    ["x-broker.txt", [], null],
    ["x-host.txt", [], null],
    ["x-provider.txt", [], null],
    ["x-provider.test-support.txt", ["test-support"], null],
    ["x-adapter.txt", [], ["registration"]],
    ["x-native.txt", [], ["NATIVE"]],
  ]);
  const withDefault = metadata([metadataPackage("x-provider", "sdk", { features: { default: ["std"], std: [], "test-support": [] } })]);
  assert.deepEqual(inventorySurfaces(withDefault, {}).map((surface) => [surface.file, surface.features]),
    [["x-provider.txt", ["default"]], ["x-provider.test-support.txt", ["default", "test-support"]]]);
});

test("every linked native or adapter needs reviewed root entry points, and no others may be listed", () => {
  const { "x-native": _native, ...withoutNative } = fixtureEntryPoints;
  assert.throws(() => inventorySurfaces(fixtureMetadata(), withoutNative), /x-native \(native\) is linked by the assembly but has no reviewed selection entry points/);
  assert.throws(() => inventorySurfaces(fixtureMetadata(), { ...fixtureEntryPoints, "x-extra": ["x_extra::EXTRA"] }),
    /x-extra has selection entry points but is not a native or adapter crate linked by the assembly/);
  assert.throws(() => inventorySurfaces(fixtureMetadata(), { ...fixtureEntryPoints, "x-reference": ["x_reference::R"] }), /x-reference/);
  for (const entry of ["x_native::module::NATIVE", "x_adapter::NATIVE", "x_native::"]) {
    assert.throws(() => inventorySurfaces(fixtureMetadata(), { ...fixtureEntryPoints, "x-native": [entry] }), /must name a root export of x_native/);
  }
  assert.throws(() => inventorySurfaces(fixtureMetadata(), { ...fixtureEntryPoints, "x-native": ["x_native::A", "x_native::A"] }), /twice/);
});

test("the reviewed entry points match the crates the repository's assembly links", () => {
  const cargoMetadata = JSON.parse(execFileSync("cargo", ["metadata", "--locked", "--no-deps", "--format-version", "1"], {
    cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
  }));
  const surfaces = inventorySurfaces(cargoMetadata);
  const files = surfaces.map((surface) => surface.file);
  for (const file of ["agent-access-provider.txt", "agent-access-provider.test-support.txt", "agent-access-broker-host.txt", "agent-access-broker.txt"]) {
    assert.ok(files.includes(file), file);
  }
  assert.deepEqual(surfaces.filter((surface) => surface.entryPoints).map((surface) => surface.package).sort(),
    Object.keys(SELECTION_ENTRY_POINTS).sort());
  assert.ok(!files.some((file) => file.startsWith("agent-access-core") || file.startsWith("agent-access-conformance")));
});

test("visible names follow re-exports and glob re-exports of private modules", () => {
  const names = visibleNames(alpha(), 0);
  assert.deepEqual([...names.keys()].sort(), ["ENTRY", "Hidden", "Renamed", "registration"]);
  assert.deepEqual(names.get("Hidden"), [6]);
  assert.deepEqual(names.get("Renamed"), [4]);
});

test("entry point pruning keeps exactly the named root exports", () => {
  const pruned = pruneToEntryPoints(alpha(), ["ENTRY", "Renamed", "Hidden"]);
  assert.deepEqual(pruned.index["0"].inner.module.items, [1, 4, 6]);
  assert.deepEqual(alpha().index["0"].inner.module.items, [1, 2, 3, 4], "the source document is unchanged");
  assert.throws(() => pruneToEntryPoints(alpha(), ["ENTRY", "MISSING"]), /alpha::MISSING is not exported by alpha/);
});

test("reachability and references skip blanket impls and local re-export targets", () => {
  const json = alpha();
  const reachable = reachableIds(json, [0]);
  assert.deepEqual([...reachable].sort((a, b) => a - b), [0, 1, 2, 3, 4, 5, 6, 7, 9]);
  assert.deepEqual([...referencedIds(json, reachable)].sort((a, b) => a - b), [6, 100, 101, 102]);
});

test("the exposure closure follows uncovered workspace types and records public dependencies", () => {
  const documents = { sdk: sdk(), "core-crate": core() };
  const loads = [];
  const load = (name, features) => {
    loads.push(`${name}:${features.join(",")}`);
    return documents[name];
  };
  const sdkReachable = reachableIds(documents.sdk, [0]);
  const coverage = (name, features) => (name === "sdk" && !features.length ? sdkReachable : null);
  const surface = { package: "alpha", file: "alpha.txt", features: [] };
  const pruned = pruneToEntryPoints(alpha(), ["ENTRY", "registration"]);
  const closure = exposureClosure({ surface, surfaceJson: pruned, resolved: resolvedFor(), workspace, load, coverage });
  assert.deepEqual(closure.sections.map((section) => [section.package, [...section.ids].sort()]), [["core-crate", [10, 13]]]);
  assert.deepEqual(closure.dependencies, ["other"]);
  assert.ok(loads.every((entry) => entry === "sdk:" || entry === "core-crate:"));

  const whole = exposureClosure({ surface, surfaceJson: alpha(), resolved: resolvedFor(), workspace, load, coverage });
  assert.deepEqual(whole.dependencies, ["other"], "the blanket impl naming `third` is not part of the inventory");

  const uncovered = exposureClosure({ surface, surfaceJson: pruned, resolved: resolvedFor(), workspace, load, coverage: () => null });
  assert.deepEqual(uncovered.sections.map((section) => section.package), ["core-crate", "sdk"]);

  const unresolved = parseResolvedPackages("alpha v0.1.0 (/checkout)\talpha\t\n");
  assert.throws(() => exposureClosure({ surface, surfaceJson: pruned, resolved: unresolved, workspace, load, coverage }),
    /belongs to (core-crate|sdk), which resolves 0 times/);
  const pathless = alpha();
  delete pathless.paths["101"];
  assert.throws(() => exposureClosure({ surface, surfaceJson: pruneToEntryPoints(pathless, ["registration"]), resolved: resolvedFor(),
    workspace, load, coverage }), /alpha\.txt: alpha names item 101, which its rustdoc JSON gives no path/);
  documents["core-crate"] = crate([module(0, "core_lib", [])], {});
  assert.throws(() => exposureClosure({ surface, surfaceJson: pruned, resolved: resolvedFor(), workspace, load, coverage }),
    /core_lib::things::Exposed \(struct\) is not in the rustdoc JSON of core-crate/);
});

test("exposed items render beneath synthetic modules at their defining paths", () => {
  const json = core();
  const synthetic = synthesizeExposure(json, new Set([13, 10]));
  const [things] = synthetic.index["0"].inner.module.items;
  const moduleItem = synthetic.index[String(things)];
  assert.equal(moduleItem.name, "things");
  assert.deepEqual(moduleItem.inner.module, { is_crate: false, items: [10, 13], is_stripped: false });
  assert.deepEqual(synthetic.paths[String(things)], { crate_id: 0, path: ["core_lib", "things"], kind: "module" });
  assert.equal(json.index[String(things)], undefined, "the source document is unchanged");
  assert.throws(() => synthesizeExposure(json, new Set([200])), /no local defining path/);
});

test("cargo tree output resolves packages, versions and features by library name", () => {
  const resolved = parseResolvedPackages([
    "agent-access-provider v0.1.0 (/checkout/crates/agent-access-provider)\tagent_access_provider\ttest-support",
    "http v1.4.2\thttp\tdefault,std",
    "http v1.4.2\thttp\tdefault,std (*)",
    "http v0.2.12\thttp\t",
    "serde_derive v1.0.228 (proc-macro)\tserde_derive\tdefault",
    "cipher v0.4.4\tcipher\t (*)",
    "",
    "agent-access v0.1.0 (/checkout/crates/agent-access)\t\t",
  ].join("\n"));
  assert.deepEqual(resolved.get("agent_access_provider"), [{ package: "agent-access-provider", version: "0.1.0",
    source: "/checkout/crates/agent-access-provider", features: ["test-support"] }]);
  assert.deepEqual(resolved.get("http").map((entry) => [entry.version, entry.features]), [["1.4.2", ["default", "std"]], ["0.2.12", []]]);
  assert.deepEqual(resolved.get("serde_derive")[0].features, ["default"]);
  assert.deepEqual(resolved.get("cipher")[0].features, []);
  assert.equal(resolved.has(""), false);
});

test("public dependencies render their semver-compatible lines", () => {
  assert.equal(compatibleLine("1.4.2"), "1");
  assert.equal(compatibleLine("0.12.28"), "0.12");
  assert.equal(compatibleLine("0.0.3"), "0.0.3");
  assert.equal(compatibleLine("2.0.0-rc.1"), "2");
  assert.throws(() => compatibleLine("1.4"), /Invalid package version/);
  const resolved = parseResolvedPackages("http v1.4.2\thttp\t\nhttp v0.2.12\thttp\t\ntokio-util v0.7.16\ttokio_util\t\n");
  assert.deepEqual(dependencyLines(["tokio_util", "http", "mystery"], resolved),
    ["dependency http 0.2, 1", "dependency mystery unresolved", "dependency tokio-util 0.7"]);
});

test("inventory text separates the surface, exposed types and public dependencies", () => {
  const surface = { package: "agent-access-jira", features: [], entryPoints: ["JIRA_BACKEND"] };
  assert.equal(renderInventory(surface, {
    own: "pub mod agent_access_jira\npub static agent_access_jira::JIRA_BACKEND: T\n",
    exposed: [{ package: "agent-access-core", features: ["test-support"], text: "pub mod agent_access_core\n" }],
    dependencies: ["dependency http 1"],
  }), [
    "// agent-access-jira selection entry points (features: none)",
    "// Generated by `node scripts/public-api.mjs update`; review changes with api/README.md.",
    "",
    "pub mod agent_access_jira",
    "pub static agent_access_jira::JIRA_BACKEND: T",
    "",
    "// Exposed through supported signatures: agent-access-core (features: test-support)",
    "",
    "pub mod agent_access_core",
    "",
    "// Public dependency packages (semver-compatible lines)",
    "",
    "dependency http 1",
    "",
  ].join("\n"));
  assert.equal(renderInventory({ package: "agent-access-provider", features: ["test-support"], entryPoints: null }, { own: "pub mod a\n" }),
    "// agent-access-provider public API (features: test-support)\n// Generated by `node scripts/public-api.mjs update`; review changes with api/README.md.\n\npub mod a\n");
});

test("comparison reports new, stale and changed surfaces with removed and added line counts", () => {
  const checked = new Map([["a.txt", "keep\nold\nold\n"], ["b.txt", "same\n"], ["stale.txt", "gone\n"]]);
  const generated = new Map([["a.txt", "keep\nold\nnew\nnewer\n"], ["b.txt", "same\n"], ["new.txt", "fresh\n"]]);
  const comparison = compareInventories(checked, generated);
  assert.deepEqual(comparison, { equal: false, missing: ["new.txt"], stale: ["stale.txt"],
    changed: [{ file: "a.txt", removed: 1, added: 2 }] });
  assert.equal(formatComparison(comparison), [
    "  api/new.txt: new surface, not checked in",
    "  api/stale.txt: no longer generated",
    "  api/a.txt: 1 line(s) removed or changed, 2 added",
  ].join("\n"));
  assert.deepEqual(compareInventories(generated, new Map(generated)), { equal: true, missing: [], stale: [], changed: [] });
});

const nightly = "/home/user/.rustup/toolchains/nightly-2026-07-13-x86_64-unknown-linux-gnu/bin";
const fakeRun = (overrides = {}) => (command, args, options) => {
  if (overrides[command]) return overrides[command](args, options);
  if (command === "rustup") {
    assert.deepEqual(args.slice(0, 3), ["which", "--toolchain", PUBLIC_API_TOOLCHAIN]);
    assert.equal(options.env.RUSTUP_TOOLCHAIN, undefined);
    assert.equal(options.env.RUSTUP_AUTO_INSTALL, "0");
    return `${nightly}/${args[3]}\n`;
  }
  const versions = { cargo: "cargo 1.99.0-nightly (59800466c 2026-07-07)", rustc: "rustc 1.99.0-nightly (77cf889bc 2026-07-12)",
    rustdoc: "rustdoc 1.99.0-nightly (77cf889bc 2026-07-12)", "cargo-public-api": `cargo-public-api ${CARGO_PUBLIC_API_VERSION}` };
  return `${versions[path.basename(command)]}\n`;
};
const locate = () => "/home/user/.cargo/bin/cargo-public-api";

test("toolchain inspection resolves the pinned nightly from the dedicated rustup home", () => {
  const env = { RUSTUP_HOME: "/opt/rustup", [RUSTUP_HOME_VARIABLE]: "/home/user/.rustup", RUSTUP_TOOLCHAIN: "1.98.1" };
  const homes = [];
  const toolchain = inspectPublicApiToolchain({ env, locate, run: fakeRun({ rustup: (args, options) => {
    homes.push(options.env.RUSTUP_HOME);
    return fakeRun()("rustup", args, options);
  } }) });
  assert.deepEqual(new Set(homes), new Set(["/home/user/.rustup"]));
  assert.deepEqual(toolchain, {
    toolchain: PUBLIC_API_TOOLCHAIN, rustupHome: "/home/user/.rustup",
    cargo: `${nightly}/cargo`, rustc: `${nightly}/rustc`, rustdoc: `${nightly}/rustdoc`,
    cargoVersion: "cargo 1.99.0-nightly (59800466c 2026-07-07)", rustcVersion: "rustc 1.99.0-nightly (77cf889bc 2026-07-12)",
    rustdocVersion: "rustdoc 1.99.0-nightly (77cf889bc 2026-07-12)",
    cargoPublicApi: "/home/user/.cargo/bin/cargo-public-api", cargoPublicApiVersion: CARGO_PUBLIC_API_VERSION, rustdocJsonFormat: 60,
  });
  assert.equal(inspectPublicApiToolchain({ env: { RUSTUP_HOME: "/opt/rustup" }, locate, run: fakeRun() }).rustupHome, "/opt/rustup");
  assert.equal(inspectPublicApiToolchain({ env: { HOME: "/home/other" }, locate, run: fakeRun() }).rustupHome, "/home/other/.rustup");
});

test("missing or mismatched tools fail with a prerequisite message instead of skipping", () => {
  const env = { RUSTUP_HOME: "/opt/rustup" };
  const missing = Object.assign(new Error("Command failed"), { stderr: `error: toolchain '${PUBLIC_API_TOOLCHAIN}' is not installed` });
  const failures = [
    [{ rustup: () => { throw missing; } }, locate, /nightly-2026-07-13 cargo was not found in rustup home \/opt\/rustup \(error: toolchain 'nightly-2026-07-13' is not installed\).*rustup toolchain install nightly-2026-07-13.*AGENT_ACCESS_PUBLIC_API_RUSTUP_HOME/],
    [{ rustup: () => { throw Object.assign(new Error("spawnSync rustup ENOENT"), { code: "ENOENT" }); } }, locate, /spawnSync rustup ENOENT/],
    [{ rustup: () => "rustdoc" }, locate, /relative cargo path/],
    [{ [`${nightly}/rustdoc`]: () => "rustdoc 1.98.1 (48a229cea 2026-09-01)" }, locate, /matching nightly rustc and rustdoc/],
    [{ [`${nightly}/rustc`]: () => "rustc 1.99.0-nightly (0000000aa 2026-07-11)" }, locate, /matching nightly rustc and rustdoc/],
    [{}, () => null, /cargo-public-api was not found on PATH.*cargo install cargo-public-api --version 0\.52\.0 --locked/],
    [{ "/home/user/.cargo/bin/cargo-public-api": () => "cargo-public-api 0.51.0" }, locate, /is 0\.51\.0; the inventory requires cargo-public-api 0\.52\.0/],
  ];
  for (const [overrides, locator, message] of failures) {
    assert.throws(() => inspectPublicApiToolchain({ env, locate: locator, run: fakeRun(overrides) }),
      (error) => error instanceof PublicApiPrerequisiteError && message.test(error.message), String(message));
  }
});

test("the command exits with a prerequisite failure when the tools are unavailable", (t) => {
  const home = mkdtempSync(path.join(tmpdir(), "public-api-rustup-"));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const result = spawnSync(process.execPath, [path.join(root, "scripts", "public-api.mjs"), "check"], {
    cwd: root, encoding: "utf8", env: { PATH: home, HOME: home, [RUSTUP_HOME_VARIABLE]: home },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /^Public API prerequisite missing: the nightly-2026-07-13 cargo was not found/);
  assert.equal(result.stdout, "");
});

test("Cargo runs the pinned nightly in the isolated target without inherited overrides", () => {
  const toolchain = { toolchain: PUBLIC_API_TOOLCHAIN, rustupHome: "/home/user/.rustup",
    cargo: `${nightly}/cargo`, rustc: `${nightly}/rustc`, rustdoc: `${nightly}/rustdoc` };
  const env = publicApiEnvironment({ PATH: "/usr/bin", CARGO_TARGET_DIR: "/elsewhere", CARGO_BUILD_TARGET_DIR: "/elsewhere",
    CARGO_BUILD_TARGET: "aarch64-unknown-linux-gnu", RUSTFLAGS: "-D warnings", RUSTDOCFLAGS: "--cfg x",
    RUSTC_WRAPPER: "sccache", RUSTUP_TOOLCHAIN: "1.98.1", RUSTC_BOOTSTRAP: "1", CARGO_INCREMENTAL: "1" }, toolchain);
  for (const name of ["CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_TARGET", "RUSTC_BOOTSTRAP"]) assert.equal(env[name], undefined, name);
  assert.equal(env.PATH, "/usr/bin");
  assert.equal(env.RUSTUP_TOOLCHAIN, PUBLIC_API_TOOLCHAIN);
  assert.equal(env.RUSTUP_HOME, "/home/user/.rustup");
  assert.equal(env.CARGO, toolchain.cargo);
  assert.equal(env.RUSTC, toolchain.rustc);
  assert.equal(env.CARGO_BUILD_RUSTDOC, toolchain.rustdoc);
  assert.equal(env.RUSTC_WRAPPER, "");
  assert.equal(env.RUSTFLAGS, "");
  assert.equal(env.RUSTDOCFLAGS, "");
  assert.equal(env.CARGO_ENCODED_RUSTFLAGS, "--cap-lints=allow");
  assert.equal(env.CARGO_INCREMENTAL, "0");
  const target = path.join(root, "target", "public-api");
  assert.deepEqual(rustdocArguments("agent-access-provider", ["test-support"], target), ["rustdoc", "--locked", "--quiet",
    "-p", "agent-access-provider", "--lib", "--target-dir", target, "--no-default-features", "--features", "test-support",
    "--", "-Z", "unstable-options", "--output-format", "json", "--cap-lints", "allow"]);
  assert.deepEqual(rustdocArguments("agent-access-broker", [], target).slice(4, 9),
    ["agent-access-broker", "--lib", "--target-dir", target, "--no-default-features"]);
  assert.deepEqual(treeArguments("agent-access-broker-host", []), ["tree", "--locked", "-p", "agent-access-broker-host",
    "--no-default-features", "-e", "normal", "--prefix", "none", "--format", "{p}\t{lib}\t{f}"]);
});
