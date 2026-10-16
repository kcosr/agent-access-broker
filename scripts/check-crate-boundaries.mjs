#!/usr/bin/env node
// Check workspace crate dependency boundaries from locked Cargo metadata.
// Every member declares `[package.metadata.agent-access] role`; see docs/testing.md.
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const ROOT = resolve(dirname(SCRIPT_PATH), "..");

export const ROLES = Object.freeze(["sdk", "core", "host", "assembly", "cli", "native", "reference", "adapter", "helper"]);
const PRODUCTION_KINDS = new Set(["normal", "build"]);

// Production closures that must stay free of these roles. The CLI's current
// core dependency is internal product implementation and is reported, not rejected.
const PRODUCTION_CLOSURE_FORBIDDEN = Object.freeze({
  core: ["native", "adapter", "reference"],
  host: ["native", "adapter", "reference"],
  cli: ["host", "assembly", "native", "adapter", "reference"],
});
const PRODUCTION_CLOSURE_REPORTED = Object.freeze({ cli: ["core"] });
// Direct edges of any kind (normal, build or dev) that a role must not have.
const FORBIDDEN_EDGES = Object.freeze({
  native: ["core", "host", "assembly", "cli", "adapter"],
  reference: ["core", "host", "assembly", "cli", "adapter"],
  helper: ["core", "host", "assembly", "cli", "adapter"],
});
// Roles that an adapter's production edges may reach.
const ADAPTER_PRODUCTION_TARGETS = new Set(["sdk", "helper", "core"]);
// Host-only items. The SDK's `authorize_host_request` hands back a request
// carrying a credential, and its `token_as_basic` presents token material as
// HTTP Basic under a host-configured username. Core's
// `gateway_upstream_authorization` presents a Git gateway's credential, through
// `token_as_basic` when configured; adapters depend on core, so the name is
// fenced as well. Provider, adapter, reference and helper code presents
// credentials only through the upstream client's send methods, in their own
// scheme or a placement of its own, so none of their sources, tests included,
// may name these, however they are imported.
export const HOST_ONLY_ITEMS = Object.freeze([
  "authorize_host_request",
  "token_as_basic",
  "gateway_upstream_authorization",
]);
const HOST_ONLY_FENCED_ROLES = Object.freeze(["native", "adapter", "reference", "helper"]);
// The Rust source locations of a package, relative to its manifest directory.
const SOURCE_ROOTS = Object.freeze(["src", "tests", "benches", "examples", "build.rs"]);

// Builds the workspace-member dependency graph. Edge kinds come from the
// resolved graph, so optional dependencies count when metadata enables all features.
export function workspaceGraph(metadata) {
  const memberIds = new Set(metadata.workspace_members ?? []);
  const members = new Map();
  const errors = [];
  for (const pkg of metadata.packages ?? []) {
    if (!memberIds.has(pkg.id)) continue;
    const role = pkg.metadata?.["agent-access"]?.role;
    if (!ROLES.includes(role)) {
      errors.push(`${pkg.name}: missing or unknown [package.metadata.agent-access] role ${JSON.stringify(role ?? null)}; expected one of ${ROLES.join(", ")}`);
    }
    members.set(pkg.id, { id: pkg.id, name: pkg.name, role });
  }
  for (const id of memberIds) {
    if (!members.has(id)) errors.push(`workspace member ${id} is missing from cargo metadata packages`);
  }
  if (!metadata.resolve?.nodes) errors.push("cargo metadata has no resolved dependency graph");
  const edges = new Map([...members.keys()].map((id) => [id, []]));
  for (const node of metadata.resolve?.nodes ?? []) {
    if (!members.has(node.id)) continue;
    for (const dep of node.deps ?? []) {
      if (!members.has(dep.pkg)) continue;
      const kinds = new Set((dep.dep_kinds ?? []).map((entry) => entry.kind ?? "normal"));
      if (!kinds.size) kinds.add("normal");
      edges.get(node.id).push({ to: dep.pkg, kinds });
    }
  }
  return { members, edges, errors };
}

function productionClosure(graph, start) {
  const seen = new Set();
  const pending = [start];
  while (pending.length) {
    const id = pending.pop();
    for (const edge of graph.edges.get(id) ?? []) {
      if (seen.has(edge.to) || ![...edge.kinds].some((kind) => PRODUCTION_KINDS.has(kind))) continue;
      seen.add(edge.to);
      pending.push(edge.to);
    }
  }
  seen.delete(start);
  return seen;
}

const describe = (member) => `${member.name} (${member.role})`;
const kindList = (kinds) => [...kinds].sort().join("+");

export function checkCrateBoundaries(metadata) {
  const graph = workspaceGraph(metadata);
  const errors = [...graph.errors];
  const notes = [];
  // An undeclared role fails closed; rules below only judge declared roles.
  if (errors.length) return { errors, notes };
  const byName = (left, right) => left.name.localeCompare(right.name);
  for (const member of [...graph.members.values()].sort(byName)) {
    const edges = graph.edges.get(member.id)
      .map((edge) => ({ ...edge, target: graph.members.get(edge.to) }))
      .sort((left, right) => byName(left.target, right.target));
    if (member.role === "sdk") {
      for (const edge of edges) {
        errors.push(`${describe(member)} must have no workspace dependency; found ${kindList(edge.kinds)} edge to ${describe(edge.target)}`);
      }
    }
    for (const edge of edges) {
      if ((FORBIDDEN_EDGES[member.role] ?? []).includes(edge.target.role)) {
        errors.push(`${describe(member)} must not depend on ${edge.target.role} crates; found ${kindList(edge.kinds)} edge to ${describe(edge.target)}`);
      }
    }
    if (member.role === "adapter") {
      for (const edge of edges) {
        if ([...edge.kinds].some((kind) => PRODUCTION_KINDS.has(kind)) && !ADAPTER_PRODUCTION_TARGETS.has(edge.target.role)) {
          errors.push(`${describe(member)} production dependencies may reach only sdk, helper or core crates; found ${kindList(edge.kinds)} edge to ${describe(edge.target)}`);
        }
      }
    }
    const forbidden = PRODUCTION_CLOSURE_FORBIDDEN[member.role];
    const reported = PRODUCTION_CLOSURE_REPORTED[member.role] ?? [];
    if (!forbidden) continue;
    const closure = [...productionClosure(graph, member.id)].map((id) => graph.members.get(id)).sort(byName);
    for (const target of closure) {
      if (forbidden.includes(target.role)) {
        errors.push(`${describe(member)} production closure must not include ${target.role} crates; found ${describe(target)}`);
      } else if (reported.includes(target.role)) {
        notes.push(`${describe(member)} production closure includes ${describe(target)} (allowed)`);
      }
    }
  }
  return { errors, notes };
}

// Every Rust file of a package: [{ path, text }] with paths relative to `root`.
export function packageRustSources(manifestPath, root = ROOT) {
  const files = [];
  const visit = (path) => {
    if (!existsSync(path)) return;
    if (statSync(path).isDirectory()) {
      for (const entry of readdirSync(path).sort()) visit(join(path, entry));
    } else if (path.endsWith(".rs")) {
      files.push({ path: relative(root, path), text: readFileSync(path, "utf8") });
    }
  };
  for (const source of SOURCE_ROOTS) visit(join(dirname(manifestPath), source));
  return files;
}

// Uses of host-only SDK items in provider-side crates. `readSources(pkg)` returns
// the package's Rust files as [{ path, text }].
export function hostOnlyUseViolations(metadata, readSources = (pkg) => packageRustSources(pkg.manifest_path)) {
  const memberIds = new Set(metadata.workspace_members ?? []);
  const pattern = new RegExp(`\\b(${HOST_ONLY_ITEMS.join("|")})\\b`);
  const errors = [];
  const packages = (metadata.packages ?? [])
    .filter((pkg) => memberIds.has(pkg.id) && HOST_ONLY_FENCED_ROLES.includes(pkg.metadata?.["agent-access"]?.role))
    .sort((left, right) => left.name.localeCompare(right.name));
  for (const pkg of packages) {
    const role = pkg.metadata["agent-access"].role;
    for (const { path, text } of readSources(pkg)) {
      text.split("\n").forEach((line, index) => {
        const found = line.match(pattern);
        if (found) {
          errors.push(`${pkg.name} (${role}) must not use host-only ${found[1]}; found at ${path}:${index + 1}`);
        }
      });
    }
  }
  return errors;
}

export function cargoMetadata(root = ROOT, env = process.env) {
  const cargo = env.CARGO || "cargo";
  return JSON.parse(execFileSync(cargo, ["metadata", "--locked", "--format-version", "1", "--all-features"], {
    cwd: root, env, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "inherit"],
  }));
}

function main() {
  const metadata = cargoMetadata();
  const { errors, notes } = checkCrateBoundaries(metadata);
  errors.push(...hostOnlyUseViolations(metadata));
  for (const note of notes) console.log(`note: ${note}`);
  if (errors.length) {
    console.error(errors.map((error) => `error: ${error}`).join("\n"));
    process.exitCode = 1;
  } else {
    console.log(`Checked crate boundaries for ${metadata.workspace_members.length} workspace members.`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === SCRIPT_PATH) main();
