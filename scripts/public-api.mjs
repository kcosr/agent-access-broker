#!/usr/bin/env node
// Generate or check the supported public API inventory under api/.
// See api/README.md for the surfaces, the pinned tools and the review rules.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync,
  writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const ROOT = resolve(dirname(SCRIPT_PATH), "..");

export const PUBLIC_API_TOOLCHAIN = "nightly-2026-07-13";
export const CARGO_PUBLIC_API_VERSION = "0.52.0";
export const RUSTDOC_JSON_FORMAT = 60;
export const RUSTUP_HOME_VARIABLE = "AGENT_ACCESS_PUBLIC_API_RUSTUP_HOME";
export const INVENTORY_DIRECTORY = "api";
export const TARGET_DIRECTORY = join("target", "public-api");
const USAGE = "Usage: node scripts/public-api.mjs check|update";
const TEST_SUPPORT = "test-support";
// Inventoried whole: the SDK, the host and the assembly library.
const FULL_SURFACE_ROLES = new Set(["sdk", "host", "assembly"]);
// Also inventoried with their test-support feature, when they declare one.
const TEST_SUPPORT_ROLES = new Set(["sdk", "host"]);
// Inventoried through their reviewed selection entry points only.
const SELECTION_ROLES = new Set(["native", "adapter"]);
const SYSROOT_CRATES = new Set(["core", "alloc", "std", "proc_macro", "test"]);
const CAPTURE_MAX_BYTES = 512 * 1024 * 1024;
const DIFF_LINE_LIMIT = 4000;

// The reviewed selection entry points of every native, OAuth-dialect and import
// adapter crate the assembly links. Each path names a root export.
export const SELECTION_ENTRY_POINTS = Object.freeze({
  "agent-access-cloudbees-ci": ["agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND"],
  "agent-access-confluence": ["agent_access_confluence::CONFLUENCE_BACKEND"],
  "agent-access-fake": ["agent_access_fake::FAKE_BACKEND", "agent_access_fake::OAUTH_STUB_BACKEND",
    "agent_access_fake::STUB_OAUTH_DIALECT"],
  "agent-access-gitlab": ["agent_access_gitlab::GITLAB_BACKEND"],
  "agent-access-gmail": ["agent_access_gmail::GMAIL_BACKEND", "agent_access_gmail::GOOGLE_OAUTH_DIALECT"],
  "agent-access-jira": ["agent_access_jira::JIRA_BACKEND"],
  "agent-access-mcp-upstream": ["agent_access_mcp_upstream::registration"],
  "agent-access-openapi-upstream": ["agent_access_openapi_upstream::registration"],
  "agent-access-teams": ["agent_access_teams::TEAMS_BACKEND"],
});

export class PublicApiPrerequisiteError extends Error {
  constructor(message) {
    super(message);
    this.name = "PublicApiPrerequisiteError";
  }
}

export function parsePublicApiArguments(args) {
  if (args.length !== 1 || !["check", "update"].includes(args[0])) throw new Error(USAGE);
  return { mode: args[0] };
}

const sortedUnique = (values) => [...new Set(values)].sort();
const featureLabel = (features) => (features.length ? features.join(", ") : "none");
const sameFeatures = (left, right) => left.join(",") === right.join(",");

// The surface's file name: `<package>[.<features>].txt`.
export function surfaceFile(surface) {
  return `${surface.package}${surface.requested.length ? `.${surface.requested.join("+")}` : ""}.txt`;
}

const roleOf = (pkg) => pkg.metadata?.["agent-access"]?.role;
const libraryOf = (pkg) => pkg.targets?.find((target) => target.kind.includes("lib"))?.name;

// The supported surfaces, from `cargo metadata --no-deps` and the reviewed
// selection entry points. Every native or adapter crate an assembly links must
// have entry points, and every entry point must belong to such a crate. A
// surface names its requested features, which select its file; the features
// Cargo activates for them come from `resolvedSurfaceFeatures`.
export function inventorySurfaces(metadata, entryPoints = SELECTION_ENTRY_POINTS) {
  const members = new Set(metadata.workspace_members ?? []);
  const packages = (metadata.packages ?? []).filter((pkg) => members.has(pkg.id))
    .sort((left, right) => left.name.localeCompare(right.name));
  const byName = new Map(packages.map((pkg) => [pkg.name, pkg]));
  const errors = [];
  const surfaces = [];
  const surface = (pkg, requested, selection = null) => {
    const library = libraryOf(pkg);
    if (!library) {
      errors.push(`${pkg.name} (${roleOf(pkg)}) has no library target to inventory`);
      return;
    }
    const entry = { package: pkg.name, library, role: roleOf(pkg), requested, entryPoints: selection };
    surfaces.push({ ...entry, file: surfaceFile(entry) });
  };
  for (const pkg of packages) {
    if (!FULL_SURFACE_ROLES.has(roleOf(pkg))) continue;
    surface(pkg, []);
    if (TEST_SUPPORT_ROLES.has(roleOf(pkg)) && pkg.features?.[TEST_SUPPORT]) surface(pkg, [TEST_SUPPORT]);
  }
  const shipped = new Set();
  for (const assembly of packages.filter((pkg) => roleOf(pkg) === "assembly")) {
    for (const dependency of assembly.dependencies ?? []) {
      const target = byName.get(dependency.name);
      if (dependency.kind == null && target && SELECTION_ROLES.has(roleOf(target))) shipped.add(target.name);
    }
  }
  for (const name of [...shipped].sort()) {
    const pkg = byName.get(name);
    const paths = entryPoints[name] ?? [];
    if (!paths.length) {
      errors.push(`${name} (${roleOf(pkg)}) is linked by the assembly but has no reviewed selection entry points in SELECTION_ENTRY_POINTS`);
      continue;
    }
    const library = libraryOf(pkg);
    const names = [];
    for (const path of paths) {
      const segments = path.split("::");
      if (segments.length !== 2 || segments[0] !== library || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(segments[1])) {
        errors.push(`${name} selection entry point ${path} must name a root export of ${library}`);
      } else {
        names.push(segments[1]);
      }
    }
    if (new Set(names).size !== names.length) errors.push(`${name} lists a selection entry point twice`);
    surface(pkg, [], names);
  }
  for (const name of Object.keys(entryPoints).sort()) {
    if (!shipped.has(name)) {
      errors.push(`${name} has selection entry points but is not a native or adapter crate linked by the assembly`);
    }
  }
  if (errors.length) throw new Error(`Public API surfaces are inconsistent:\n${errors.map((error) => `  ${error}`).join("\n")}`);
  return surfaces;
}

// rustdoc JSON (format 60) helpers.
const itemOf = (json, id) => json.index[String(id)];
const kindOf = (item) => Object.keys(item.inner)[0];

function structFields(kind) {
  if (!kind || typeof kind !== "object") return [];
  if (kind.plain) return kind.plain.fields;
  if (kind.tuple) return kind.tuple.filter((id) => id != null);
  return [];
}

function variantFields(kind) {
  if (!kind || typeof kind !== "object") return [];
  if (kind.tuple) return kind.tuple.filter((id) => id != null);
  if (kind.struct) return kind.struct.fields;
  return [];
}

// The items cargo-public-api renders beneath an item. Blanket impls are
// omitted from the inventory, so they are not followed.
export function itemChildren(item) {
  const kind = kindOf(item);
  const inner = item.inner[kind];
  switch (kind) {
    case "module": return inner.items;
    case "use": return inner.id == null ? [] : [inner.id];
    case "struct": return [...structFields(inner.kind), ...inner.impls];
    case "union": return [...inner.fields, ...inner.impls];
    case "enum": return [...inner.variants, ...inner.impls];
    case "variant": return variantFields(inner.kind);
    case "trait": return inner.items;
    case "impl": return inner.items;
    default: return [];
  }
}

const isBlanketImpl = (item) => kindOf(item) === "impl" && item.inner.impl.blanket_impl != null;

// Local items reachable from the start IDs as the inventory renders them.
export function reachableIds(json, start) {
  const seen = new Set();
  const pending = [...start];
  while (pending.length) {
    const id = pending.pop();
    if (seen.has(id)) continue;
    const item = itemOf(json, id);
    if (!item || isBlanketImpl(item)) continue;
    seen.add(id);
    pending.push(...itemChildren(item));
  }
  return seen;
}

function collectPathIds(value, out) {
  if (Array.isArray(value)) {
    for (const entry of value) collectPathIds(entry, out);
  } else if (value && typeof value === "object") {
    if (typeof value.path === "string" && typeof value.id === "number") out.add(value.id);
    for (const entry of Object.values(value)) collectPathIds(entry, out);
  }
}

// The IDs the given items name: resolved type and trait paths in their
// signatures, bounds, fields and impl headers, plus re-exports of other
// crates' items. Local re-export targets are reached by `reachableIds`.
export function referencedIds(json, ids) {
  const out = new Set();
  for (const id of ids) {
    const item = itemOf(json, id);
    if (kindOf(item) === "use") {
      if (item.inner.use.id != null && !itemOf(json, item.inner.use.id)) out.add(item.inner.use.id);
    } else {
      collectPathIds(item.inner, out);
    }
  }
  return out;
}

// The crate, defining path and kind of a referenced ID.
export function describeReference(json, id) {
  const summary = json.paths[String(id)];
  if (!summary) return null;
  const local = summary.crate_id === 0;
  const crate = local ? itemOf(json, json.root).name : json.external_crates[String(summary.crate_id)]?.name;
  return { crate, path: summary.path, kind: summary.kind, local };
}

// The local ID with this defining path and kind.
export function findLocalItem(json, path, kind) {
  const wanted = path.join("::");
  for (const [id, summary] of Object.entries(json.paths)) {
    if (summary.crate_id === 0 && summary.kind === kind && summary.path.join("::") === wanted) return Number(id);
  }
  return null;
}

// Names visible in a module: its own items and re-exports first, then names
// brought in by glob re-exports of local modules.
export function visibleNames(json, moduleId, seen = new Set()) {
  const names = new Map();
  if (seen.has(moduleId)) return names;
  seen.add(moduleId);
  const add = (name, id) => names.set(name, [...(names.get(name) ?? []), id]);
  const globs = [];
  for (const id of itemOf(json, moduleId).inner.module.items) {
    const item = itemOf(json, id);
    if (!item) continue;
    if (kindOf(item) === "use") {
      const use = item.inner.use;
      if (!use.is_glob) add(use.name, id);
      else if (use.id != null && itemOf(json, use.id) && kindOf(itemOf(json, use.id)) === "module") globs.push(use.id);
    } else if (item.name) {
      add(item.name, id);
    }
  }
  for (const glob of globs) {
    for (const [name, ids] of visibleNames(json, glob, seen)) if (!names.has(name)) names.set(name, ids);
  }
  return names;
}

const withRootItems = (json, items) => {
  const root = itemOf(json, json.root);
  return { ...json, index: { ...json.index,
    [String(json.root)]: { ...root, inner: { module: { ...root.inner.module, items } } } } };
};

// The crate restricted to the named root exports.
export function pruneToEntryPoints(json, names) {
  const crate = itemOf(json, json.root).name;
  const visible = visibleNames(json, json.root);
  const items = [];
  for (const name of names) {
    const ids = visible.get(name);
    if (!ids?.length) throw new Error(`Selection entry point ${crate}::${name} is not exported by ${crate}`);
    items.push(...ids);
  }
  return withRootItems(json, items);
}

// A crate whose root holds only the given items, each beneath synthetic
// modules that reproduce its defining path, as signatures elsewhere name it.
export function synthesizeExposure(json, ids) {
  const root = itemOf(json, json.root);
  const index = { ...json.index };
  const paths = { ...json.paths };
  let next = Math.max(...Object.keys(index).map(Number), ...Object.keys(paths).map(Number)) + 1;
  const tree = { items: [], modules: new Map() };
  for (const id of [...ids].sort((left, right) => left - right)) {
    const summary = json.paths[String(id)];
    if (!summary || summary.crate_id !== 0) throw new Error(`Exposed item ${id} of ${root.name} has no local defining path`);
    let node = tree;
    for (const segment of summary.path.slice(1, -1)) {
      if (!node.modules.has(segment)) node.modules.set(segment, { items: [], modules: new Map() });
      node = node.modules.get(segment);
    }
    node.items.push(id);
  }
  const build = (node, prefix) => [...node.items, ...[...node.modules].sort(([left], [right]) => left.localeCompare(right))
    .map(([name, child]) => {
      const id = next++;
      const items = build(child, [...prefix, name]);
      index[String(id)] = { ...root, id, name, docs: null, attrs: [], links: {},
        inner: { module: { is_crate: false, items, is_stripped: false } } };
      paths[String(id)] = { crate_id: 0, path: [...prefix, name], kind: "module" };
      return id;
    })];
  const items = build(tree, [root.name]);
  return withRootItems({ ...json, index, paths }, items);
}

// Parses `cargo tree --prefix none --format "{p}\t{lib}\t{f}"` into resolved
// packages by library name.
export function parseResolvedPackages(output) {
  const libraries = new Map();
  for (const line of output.split(/\r?\n/)) {
    const [unit = "", library = "", features = ""] = line.split("\t");
    const pkg = /^(\S+) v(\S+)(?: \(proc-macro\))?(?: \((.*)\))?$/.exec(unit.trim());
    if (!pkg || !library.trim()) continue;
    const entries = libraries.get(library.trim()) ?? [];
    let entry = entries.find((candidate) => candidate.package === pkg[1] && candidate.version === pkg[2]
      && candidate.source === (pkg[3] ?? null));
    if (!entry) {
      entry = { package: pkg[1], version: pkg[2], source: pkg[3] ?? null, features: [] };
      entries.push(entry);
    }
    entry.features = sortedUnique([...entry.features, ...features.replace(/\s*\(\*\)\s*$/, "").split(",")
      .map((feature) => feature.trim()).filter(Boolean)]);
    libraries.set(library.trim(), entries);
  }
  return libraries;
}

// The paths at which the inventory names each local item: module paths from
// the root, with re-exports under their exported names and glob re-exports
// inlined into the re-exporting module.
export function publicPaths(json) {
  const paths = new Map();
  const seen = new Set();
  const visit = (id, prefix, name) => {
    const item = itemOf(json, id);
    if (!item) return;
    if (kindOf(item) === "use") {
      const use = item.inner.use;
      const target = use.id == null ? null : itemOf(json, use.id);
      if (!target) return;
      if (!use.is_glob) {
        visit(use.id, prefix, use.name);
      } else if (kindOf(target) === "module" && !seen.has(`glob ${use.id} ${prefix.join("::")}`)) {
        seen.add(`glob ${use.id} ${prefix.join("::")}`);
        for (const child of target.inner.module.items) visit(child, prefix);
      }
      return;
    }
    const path = [...prefix, name ?? item.name];
    const key = `${id} ${path.join("::")}`;
    if (seen.has(key)) return;
    seen.add(key);
    paths.set(id, [...(paths.get(id) ?? []), path.join("::")]);
    if (kindOf(item) === "module") for (const child of item.inner.module.items) visit(child, path);
  };
  visit(json.root, []);
  return paths;
}

const isNonExhaustive = (item) => (item.attrs ?? []).includes("non_exhaustive");

function traitMemberContract(member) {
  const kind = kindOf(member);
  const inner = member.inner[kind];
  if (kind === "function") return `${inner.has_body ? "provided" : "required"} fn`;
  if (kind === "assoc_type") return `${inner.type == null ? "required" : "provided"} type`;
  if (kind === "assoc_const") return `${inner.value == null ? "required" : "provided"} const`;
  return null;
}

function fieldsContract(kind) {
  if (kind === "unit" || kind === "plain") return ["unit"];
  if (kind?.plain) return ["named fields", ...(kind.plain.has_stripped_fields ? ["private fields"] : [])];
  if (kind?.tuple) return ["tuple fields", ...(kind.tuple.some((id) => id == null) ? ["private fields"] : [])];
  if (kind?.struct) return ["named fields", ...(kind.struct.has_stripped_fields ? ["private fields"] : [])];
  return [];
}

// Source-breaking facts that the rendered signatures omit, one line each:
// whether each trait method, associated type and constant is required or has
// a default, trait dyn compatibility and safety, how structs and variants are
// constructed (unit, tuple or named fields, private fields, non-exhaustive),
// and whether enums are exhaustive or hide variants.
export function contractLines(json) {
  const lines = [];
  for (const [id, paths] of publicPaths(json)) {
    const item = itemOf(json, id);
    const kind = kindOf(item);
    const inner = item.inner[kind];
    for (const path of paths) {
      if (kind === "trait") {
        lines.push(`trait ${path}: ${[inner.is_dyn_compatible ? "dyn-compatible" : "not dyn-compatible",
          ...(inner.is_unsafe ? ["unsafe to implement"] : [])].join(", ")}`);
        for (const memberId of inner.items) {
          const member = itemOf(json, memberId);
          const contract = member && traitMemberContract(member);
          if (contract) lines.push(`trait ${path}::${member.name}: ${contract}`);
        }
      } else if (kind === "struct" || kind === "union") {
        const fields = kind === "union" ? ["named fields", ...(inner.has_stripped_fields ? ["private fields"] : [])] : fieldsContract(inner.kind);
        lines.push(`${kind} ${path}: ${[...fields, ...(isNonExhaustive(item) ? ["non-exhaustive"] : [])].join(", ")}`);
      } else if (kind === "enum") {
        lines.push(`enum ${path}: ${[isNonExhaustive(item) ? "non-exhaustive" : "exhaustive",
          ...(inner.has_stripped_variants ? ["hidden variants"] : [])].join(", ")}`);
        for (const variantId of inner.variants) {
          const variant = itemOf(json, variantId);
          if (!variant) continue;
          const facts = fieldsContract(variant.inner.variant.kind);
          if (isNonExhaustive(variant) || facts.includes("private fields")) {
            lines.push(`variant ${path}::${variant.name}: ${[...facts, ...(isNonExhaustive(variant) ? ["non-exhaustive"] : [])].join(", ")}`);
          }
        }
      }
    }
  }
  return sortedUnique(lines);
}

// The features Cargo activates for a surface package with its default and
// requested features: the `{f}` set from `cargo tree`, which includes local
// features that other features enable. Generation, coverage and exposure all
// use these expanded sets, as `cargo tree` reports them for dependencies too.
export function resolvedSurfaceFeatures(surface, resolved) {
  const own = (resolved.get(surface.library) ?? []).filter((entry) => entry.package === surface.package);
  if (own.length !== 1) {
    throw new Error(`${surface.file}: cargo tree resolved ${surface.package} ${own.length} times`);
  }
  const missing = surface.requested.filter((feature) => !own[0].features.includes(feature));
  if (missing.length) {
    throw new Error(`${surface.file}: cargo tree did not activate the requested features ${missing.join(", ")} of ${surface.package}`);
  }
  return own[0].features;
}

// The semver-compatible line of a version: `1` for 1.4.2, `0.12` for 0.12.28.
export function compatibleLine(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!match) throw new Error(`Invalid package version ${version}`);
  if (match[1] !== "0") return match[1];
  if (match[2] !== "0") return `0.${match[2]}`;
  return `0.0.${match[3]}`;
}

// Workspace types reachable through a surface but not covered by an
// inventoried surface, closed over the types they in turn expose, and the
// third-party crates that every rendered signature names.
// - `surfaceJson` is the surface's crate, already restricted to its entry points.
// - `resolved` maps library names to the surface's resolved packages.
// - `workspace` maps library names to `{ package }` for workspace members.
// - `load(package, features)` returns that crate's rustdoc JSON.
// - `coverage(package, features)` returns the IDs another inventoried surface
//   renders for that crate and feature set, or null.
export function exposureClosure({ surface, surfaceJson, resolved, workspace, load, coverage }) {
  const own = reachableIds(surfaceJson, [surfaceJson.root]);
  const covered = (pkg, features, id) => (pkg === surface.package && sameFeatures(features, surface.features)
    ? own.has(id) : coverage(pkg, features)?.has(id) ?? false);
  const exposed = new Map();
  const dependencies = new Set();
  const pending = [{ json: surfaceJson, package: surface.package, features: surface.features,
    ids: referencedIds(surfaceJson, own) }];
  while (pending.length) {
    const { json, package: source, features: sourceFeatures, ids } = pending.pop();
    for (const id of ids) {
      if (itemOf(json, id) && covered(source, sourceFeatures, id)) continue;
      const reference = describeReference(json, id);
      if (!reference) {
        throw new Error(`${surface.file}: ${source} names item ${id}${itemOf(json, id) ? ` (${itemOf(json, id).name})` : ""}, which its rustdoc JSON gives no path`);
      }
      if (!reference.crate) throw new Error(`${surface.file}: ${reference.path.join("::")} names an unknown external crate`);
      if (SYSROOT_CRATES.has(reference.crate)) continue;
      const member = workspace.get(reference.crate);
      if (!member) {
        dependencies.add(reference.crate);
        continue;
      }
      let target = { json, package: source, features: sourceFeatures, id };
      if (!reference.local) {
        const packages = resolved.get(reference.crate)?.filter((entry) => entry.package === member.package) ?? [];
        if (packages.length !== 1) {
          throw new Error(`${surface.file}: ${reference.path.join("::")} belongs to ${member.package}, which resolves ${packages.length} times in the surface's dependency graph`);
        }
        const targetJson = load(member.package, packages[0].features);
        const targetId = findLocalItem(targetJson, reference.path, reference.kind);
        if (targetId == null) {
          throw new Error(`${surface.file}: ${reference.path.join("::")} (${reference.kind}) is not in the rustdoc JSON of ${member.package} (features: ${featureLabel(packages[0].features)})`);
        }
        target = { json: targetJson, package: member.package, features: packages[0].features, id: targetId };
      }
      if (covered(target.package, target.features, target.id)) continue;
      const key = `${target.package}\0${target.features.join(",")}`;
      if (!exposed.has(key)) {
        exposed.set(key, { package: target.package, features: target.features, json: target.json, ids: new Set() });
      }
      const entry = exposed.get(key);
      if (entry.ids.has(target.id)) continue;
      entry.ids.add(target.id);
      pending.push({ json: target.json, package: target.package, features: target.features,
        ids: referencedIds(target.json, reachableIds(target.json, [target.id])) });
    }
  }
  const sections = [...exposed.values()].sort((left, right) => left.package.localeCompare(right.package)
    || left.features.join(",").localeCompare(right.features.join(",")));
  return { sections, dependencies: [...dependencies].sort() };
}

// What the full surfaces render: for a package and an expanded feature set,
// the IDs reachable in the full surface with exactly those features, or null
// when no full surface has them. Feature sets are compared as Cargo expands
// them, for surfaces and dependencies alike.
export function surfaceCoverage(surfaces, load) {
  const sets = new Map();
  return (name, features) => {
    if (!surfaces.some((surface) => !surface.entryPoints && surface.package === name && sameFeatures(surface.features, features))) return null;
    const key = `${name}\0${features.join(",")}`;
    if (!sets.has(key)) {
      const json = load(name, features);
      sets.set(key, reachableIds(json, [json.root]));
    }
    return sets.get(key);
  };
}

// One `dependency <package> <compatible lines>` line per third-party crate
// whose items appear in the inventory.
export function dependencyLines(dependencies, resolved) {
  const lines = dependencies.map((library) => {
    const packages = resolved.get(library) ?? [];
    if (!packages.length) return `dependency ${library} unresolved`;
    const names = sortedUnique(packages.map((entry) => entry.package));
    return `dependency ${names.join(", ")} ${sortedUnique(packages.map((entry) => compatibleLine(entry.version))).join(", ")}`;
  });
  return sortedUnique(lines);
}

const GENERATED_NOTE = "// Generated by `node scripts/public-api.mjs update`; review changes with api/README.md.";

// The checked-in text for one surface.
export function renderInventory(surface, { own, exposed = [], contracts = [], dependencies = [] }) {
  const title = surface.entryPoints
    ? `// ${surface.package} selection entry points (features: ${featureLabel(surface.features)})`
    : `// ${surface.package} public API (features: ${featureLabel(surface.features)})`;
  const blocks = [[title, GENERATED_NOTE].join("\n"), own.trimEnd()];
  for (const section of exposed) {
    blocks.push(`// Exposed through supported signatures: ${section.package} (features: ${featureLabel(section.features)})`);
    blocks.push(section.text.trimEnd());
  }
  if (contracts.length) {
    blocks.push("// Implementation and construction contracts of the items above");
    blocks.push(contracts.join("\n"));
  }
  if (dependencies.length) {
    blocks.push("// Public dependency packages (semver-compatible lines)");
    blocks.push(dependencies.join("\n"));
  }
  return `${blocks.filter(Boolean).join("\n\n")}\n`;
}

function lineCounts(text) {
  const counts = new Map();
  for (const line of text.split("\n")) if (line.trim()) counts.set(line, (counts.get(line) ?? 0) + 1);
  return counts;
}

function lineDifference(left, right) {
  let count = 0;
  for (const [line, number] of left) count += Math.max(0, number - (right.get(line) ?? 0));
  return count;
}

// Compares checked-in and generated inventories, keyed by file name.
export function compareInventories(checked, generated) {
  const missing = [...generated.keys()].filter((file) => !checked.has(file)).sort();
  const stale = [...checked.keys()].filter((file) => !generated.has(file)).sort();
  const changed = [];
  for (const file of [...generated.keys()].filter((name) => checked.has(name)).sort()) {
    if (checked.get(file) === generated.get(file)) continue;
    const before = lineCounts(checked.get(file));
    const after = lineCounts(generated.get(file));
    changed.push({ file, removed: lineDifference(before, after), added: lineDifference(after, before) });
  }
  return { equal: !missing.length && !stale.length && !changed.length, missing, stale, changed };
}

export function formatComparison(comparison) {
  const lines = [];
  for (const file of comparison.missing) lines.push(`  ${INVENTORY_DIRECTORY}/${file}: new surface, not checked in`);
  for (const file of comparison.stale) lines.push(`  ${INVENTORY_DIRECTORY}/${file}: no longer generated`);
  for (const entry of comparison.changed) {
    lines.push(`  ${INVENTORY_DIRECTORY}/${entry.file}: ${entry.removed} line(s) removed or changed, ${entry.added} added`);
  }
  return lines.join("\n");
}

const REVIEW_RULES = [
  "A patch release on a compatible line must not remove or change any line: removals and signature,",
  "bound, feature or public dependency changes are breaking. Review every added line too: a new",
  "required trait method, a new enum variant on an exhaustive enum or a new public field can break",
  "downstream code. If the change is intended and reviewed, run `node scripts/public-api.mjs update`",
  "and commit api/.",
].join("\n");

// Resolves the rustup home that holds the pinned nightly: the dedicated
// variable, else the ambient rustup home.
export function publicApiRustupHome(env = process.env) {
  return env[RUSTUP_HOME_VARIABLE] || env.RUSTUP_HOME || join(env.HOME || homedir(), ".rustup");
}

function findOnPath(command, env) {
  if (isAbsolute(command)) return existsSync(command) ? command : null;
  const extensions = process.platform === "win32" ? ["", ".exe", ".cmd"] : [""];
  for (const directory of (env.PATH ?? "").split(delimiter).filter(Boolean)) {
    for (const extension of extensions) {
      const candidate = join(directory, `${command}${extension}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

function failureDetail(error) {
  const stderr = error?.stderr?.toString().trim();
  return stderr || error?.message || String(error);
}

// Locates and validates the pinned nightly rustdoc and cargo-public-api.
// Missing or mismatched tools raise a PublicApiPrerequisiteError.
export function inspectPublicApiToolchain({ env = process.env, run = execFileSync, locate = findOnPath } = {}) {
  const rustupHome = publicApiRustupHome(env);
  const toolEnv = { ...env, RUSTUP_HOME: rustupHome, RUSTUP_AUTO_INSTALL: "0" };
  delete toolEnv.RUSTUP_TOOLCHAIN;
  const output = (command, args) => run(command, args, {
    env: toolEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  }).toString().trim();
  const install = `Install it with \`RUSTUP_HOME=${rustupHome} rustup toolchain install ${PUBLIC_API_TOOLCHAIN} --profile minimal\`, or set ${RUSTUP_HOME_VARIABLE} to the rustup home that contains it.`;
  const tools = {};
  for (const tool of ["cargo", "rustc", "rustdoc"]) {
    try {
      tools[tool] = output("rustup", ["which", "--toolchain", PUBLIC_API_TOOLCHAIN, tool]);
    } catch (error) {
      throw new PublicApiPrerequisiteError(`Public API prerequisite missing: the ${PUBLIC_API_TOOLCHAIN} ${tool} was not found in rustup home ${rustupHome} (${failureDetail(error)}). ${install}`);
    }
    if (!isAbsolute(tools[tool])) {
      throw new PublicApiPrerequisiteError(`Public API prerequisite missing: rustup returned a relative ${tool} path for ${PUBLIC_API_TOOLCHAIN}. ${install}`);
    }
  }
  const versions = {};
  for (const tool of ["cargo", "rustc", "rustdoc"]) {
    try {
      versions[tool] = output(tools[tool], ["-V"]);
    } catch (error) {
      throw new PublicApiPrerequisiteError(`Public API prerequisite missing: ${tools[tool]} -V failed (${failureDetail(error)}). ${install}`);
    }
  }
  const compilerRelease = (version, tool) => new RegExp(`^${tool} (\\S+-nightly \\(\\S+ \\d{4}-\\d{2}-\\d{2}\\))$`).exec(version)?.[1];
  const release = compilerRelease(versions.rustdoc, "rustdoc");
  if (!release || release !== compilerRelease(versions.rustc, "rustc")) {
    throw new PublicApiPrerequisiteError(`Public API prerequisite mismatch: ${PUBLIC_API_TOOLCHAIN} must provide matching nightly rustc and rustdoc; found ${versions.rustc} and ${versions.rustdoc}`);
  }
  const cargoPublicApi = locate("cargo-public-api", env);
  const installTool = `Install it with \`cargo install cargo-public-api --version ${CARGO_PUBLIC_API_VERSION} --locked\` and put it on PATH.`;
  if (!cargoPublicApi) {
    throw new PublicApiPrerequisiteError(`Public API prerequisite missing: cargo-public-api was not found on PATH. ${installTool}`);
  }
  let cargoPublicApiVersion;
  try {
    cargoPublicApiVersion = /^cargo-public-api (\S+)$/.exec(output(cargoPublicApi, ["--version"]))?.[1];
  } catch (error) {
    throw new PublicApiPrerequisiteError(`Public API prerequisite missing: ${cargoPublicApi} --version failed (${failureDetail(error)}). ${installTool}`);
  }
  if (cargoPublicApiVersion !== CARGO_PUBLIC_API_VERSION) {
    throw new PublicApiPrerequisiteError(`Public API prerequisite mismatch: ${cargoPublicApi} is ${cargoPublicApiVersion ?? "an unknown version"}; the inventory requires cargo-public-api ${CARGO_PUBLIC_API_VERSION}. ${installTool}`);
  }
  return {
    toolchain: PUBLIC_API_TOOLCHAIN, rustupHome, ...tools,
    cargoVersion: versions.cargo, rustcVersion: versions.rustc, rustdocVersion: versions.rustdoc,
    cargoPublicApi, cargoPublicApiVersion, rustdocJsonFormat: RUSTDOC_JSON_FORMAT,
  };
}

// The Cargo environment for the pinned nightly: explicit tool paths, no
// wrappers or inherited flags, and no inherited target directory. Lints are
// capped and the isolated target keeps no debuginfo or incremental state: the
// inventory checks the API, not nightly diagnostics or binaries.
export function publicApiEnvironment(env, toolchain) {
  const result = { ...env };
  for (const name of ["CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_TARGET", "RUSTC_BOOTSTRAP",
    "RUSTC_STAGE", "RUST_TARGET_PATH"]) delete result[name];
  return Object.assign(result, {
    CARGO_INCREMENTAL: "0", CARGO_PROFILE_DEV_DEBUG: "0",
    RUSTUP_HOME: toolchain.rustupHome, RUSTUP_TOOLCHAIN: toolchain.toolchain, RUSTUP_AUTO_INSTALL: "0",
    CARGO: toolchain.cargo, RUSTC: toolchain.rustc, RUSTDOC: toolchain.rustdoc,
    CARGO_BUILD_RUSTC: toolchain.rustc, CARGO_BUILD_RUSTDOC: toolchain.rustdoc,
    RUSTC_WRAPPER: "", RUSTC_WORKSPACE_WRAPPER: "",
    CARGO_BUILD_RUSTC_WRAPPER: "", CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER: "",
    RUSTFLAGS: "", CARGO_ENCODED_RUSTFLAGS: "--cap-lints=allow", CARGO_BUILD_RUSTFLAGS: "",
    RUSTDOCFLAGS: "", CARGO_ENCODED_RUSTDOCFLAGS: "", CARGO_BUILD_RUSTDOCFLAGS: "",
  });
}

const featureArguments = (features) => ["--no-default-features", ...(features.length ? ["--features", features.join(",")] : [])];

export function rustdocArguments(pkg, features, targetDirectory) {
  return ["rustdoc", "--locked", "--quiet", "-p", pkg, "--lib", "--target-dir", targetDirectory,
    ...featureArguments(features), "--", "-Z", "unstable-options", "--output-format", "json", "--cap-lints", "allow"];
}

// Resolves a surface with its default features and the requested ones.
export function treeArguments(pkg, requested) {
  return ["tree", "--locked", "-p", pkg, ...(requested.length ? ["--features", requested.join(",")] : []),
    "-e", "normal", "--prefix", "none", "--format", "{p}\t{lib}\t{f}"];
}

export const CARGO_PUBLIC_API_ARGUMENTS = Object.freeze(["--color", "never", "--omit", "blanket-impls"]);

function capture(command, args, { cwd, env }) {
  try {
    return execFileSync(command, args, { cwd, env, encoding: "utf8", maxBuffer: CAPTURE_MAX_BYTES,
      stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    throw new Error(`${command} ${args.join(" ")} failed: ${failureDetail(error)}`);
  }
}

// Generates every surface's inventory text from the working tree.
export function generateInventories({ root = ROOT, env = process.env, toolchain, log = console.error } = {}) {
  const cargoEnv = publicApiEnvironment(env, toolchain);
  const targetDirectory = join(root, TARGET_DIRECTORY);
  const scratch = mkdtempSync(join(tmpdir(), "agent-access-public-api-"));
  try {
    const metadata = JSON.parse(capture(toolchain.cargo, ["metadata", "--locked", "--no-deps", "--format-version", "1"],
      { cwd: root, env: cargoEnv }));
    const resolutions = new Map();
    const surfaces = inventorySurfaces(metadata).map((surface) => {
      const resolved = parseResolvedPackages(capture(toolchain.cargo, treeArguments(surface.package, surface.requested),
        { cwd: root, env: cargoEnv }));
      resolutions.set(surface.file, resolved);
      return { ...surface, features: resolvedSurfaceFeatures(surface, resolved) };
    });
    const members = new Set(metadata.workspace_members);
    const packages = new Map(metadata.packages.filter((pkg) => members.has(pkg.id)).map((pkg) => [pkg.name, pkg]));
    const workspace = new Map([...packages.values()].filter(libraryOf).map((pkg) => [libraryOf(pkg), { package: pkg.name }]));
    const documents = new Map();
    const load = (name, features) => {
      const key = `${name}\0${features.join(",")}`;
      if (documents.has(key)) return documents.get(key);
      log(`public-api: documenting ${name} (features: ${featureLabel(features)})`);
      const output = join(targetDirectory, "doc", `${libraryOf(packages.get(name))}.json`);
      rmSync(output, { force: true });
      const run = spawnSync(toolchain.cargo, rustdocArguments(name, features, targetDirectory), {
        cwd: root, env: cargoEnv, stdio: ["ignore", "inherit", "inherit"],
      });
      if (run.error || run.status !== 0 || !existsSync(output)) {
        throw new Error(`cargo rustdoc for ${name} (features: ${featureLabel(features)}) failed${run.error ? `: ${run.error.message}` : ` with status ${run.status}`}`);
      }
      const json = JSON.parse(readFileSync(output, "utf8"));
      if (json.format_version !== RUSTDOC_JSON_FORMAT) {
        throw new Error(`rustdoc JSON for ${name} has format ${json.format_version}; the inventory requires format ${RUSTDOC_JSON_FORMAT} from ${PUBLIC_API_TOOLCHAIN}`);
      }
      documents.set(key, json);
      return json;
    };
    const coverage = surfaceCoverage(surfaces, load);
    let renders = 0;
    const render = (json) => {
      const file = join(scratch, `render-${renders++}.json`);
      writeFileSync(file, JSON.stringify(json));
      try {
        return capture(toolchain.cargoPublicApi, ["--rustdoc-json", file, ...CARGO_PUBLIC_API_ARGUMENTS], { cwd: scratch, env });
      } finally {
        rmSync(file, { force: true });
      }
    };
    const inventories = new Map();
    for (const surface of surfaces) {
      log(`public-api: rendering ${surface.file}`);
      const resolved = resolutions.get(surface.file);
      const document = load(surface.package, surface.features);
      const surfaceJson = surface.entryPoints ? pruneToEntryPoints(document, surface.entryPoints) : document;
      const closure = exposureClosure({ surface, surfaceJson, resolved, workspace, load, coverage });
      const exposed = closure.sections.map((section) => ({ ...section, json: synthesizeExposure(section.json, section.ids) }));
      inventories.set(surface.file, renderInventory(surface, {
        own: render(surfaceJson),
        exposed: exposed.map((section) => ({ ...section, text: render(section.json) })),
        contracts: sortedUnique([surfaceJson, ...exposed.map((section) => section.json)].flatMap(contractLines)),
        dependencies: dependencyLines(closure.dependencies, resolved),
      }));
    }
    return inventories;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

export function readInventories(directory) {
  const inventories = new Map();
  if (!existsSync(directory)) return inventories;
  for (const file of readdirSync(directory).filter((name) => name.endsWith(".txt")).sort()) {
    inventories.set(file, readFileSync(join(directory, file), "utf8"));
  }
  return inventories;
}

// A unified diff of the checked-in and generated inventories, labelled
// `checked/` and `generated/`.
function inventoryDiff(checked, generated, env) {
  const scratch = mkdtempSync(join(tmpdir(), "agent-access-public-api-diff-"));
  try {
    for (const [side, inventories] of [["checked", checked], ["generated", generated]]) {
      mkdirSync(join(scratch, side));
      for (const [file, text] of inventories) writeFileSync(join(scratch, side, file), text);
    }
    const diff = spawnSync("git", ["diff", "--no-index", "--no-color", "--no-ext-diff", "--no-renames", "--", "checked", "generated"],
      { cwd: scratch, env, encoding: "utf8", maxBuffer: CAPTURE_MAX_BYTES });
    if (diff.error || ![0, 1].includes(diff.status)) return `(git diff unavailable: ${diff.error?.message ?? diff.stderr?.trim()})`;
    const lines = diff.stdout.split("\n");
    return lines.length > DIFF_LINE_LIMIT
      ? `${lines.slice(0, DIFF_LINE_LIMIT).join("\n")}\n... diff truncated after ${DIFF_LINE_LIMIT} lines`
      : diff.stdout.trimEnd();
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

export function describeToolchain(toolchain) {
  return `${toolchain.rustdocVersion} (${toolchain.toolchain} in ${toolchain.rustupHome}), rustdoc JSON format ${toolchain.rustdocJsonFormat}, cargo-public-api ${toolchain.cargoPublicApiVersion} (${toolchain.cargoPublicApi})`;
}

// Check mode returns whether the checked-in inventory matches; update mode
// rewrites it and returns true.
export function runPublicApi({ mode, root = ROOT, env = process.env } = {}) {
  const toolchain = inspectPublicApiToolchain({ env });
  console.log(`Public API toolchain: ${describeToolchain(toolchain)}`);
  const generated = generateInventories({ root, env, toolchain });
  const directory = join(root, INVENTORY_DIRECTORY);
  const checked = readInventories(directory);
  const comparison = compareInventories(checked, generated);
  if (mode === "update") {
    mkdirSync(directory, { recursive: true });
    for (const file of comparison.stale) rmSync(join(directory, file));
    for (const [file, text] of generated) writeFileSync(join(directory, file), text);
    console.log(comparison.equal ? `Public API inventory unchanged for ${generated.size} surfaces.`
      : `Updated the public API inventory for ${generated.size} surfaces:\n${formatComparison(comparison)}\n${REVIEW_RULES}`);
    return true;
  }
  if (comparison.equal) {
    console.log(`Public API inventory matches the candidate for ${generated.size} surfaces.`);
    return true;
  }
  console.error(`The checked-in public API inventory differs from the candidate:\n${formatComparison(comparison)}\n\n${inventoryDiff(checked, generated, env)}\n\n${REVIEW_RULES}`);
  return false;
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH)) {
  try {
    if (!runPublicApi({ ...parsePublicApiArguments(process.argv.slice(2)) })) process.exitCode = 1;
  } catch (error) {
    console.error(error.message);
    process.exitCode = error instanceof PublicApiPrerequisiteError ? 2 : 1;
  }
}
