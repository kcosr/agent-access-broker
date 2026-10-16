import assert from "node:assert/strict";
import test from "node:test";
import { HOST_ONLY_ITEMS, ROLES, checkCrateBoundaries, hostOnlyUseViolations } from "./check-crate-boundaries.mjs";

const id = (name) => `path+file:///workspace/crates/${name}#0.1.0`;

// Synthetic `cargo metadata` output. `edges` maps a crate to [dependency, ...kinds],
// where a kind of null is a normal dependency, as Cargo reports it.
function metadata(roles, edges = {}, { external = [] } = {}) {
  const packages = Object.entries(roles).map(([name, role]) => ({
    name, id: id(name), metadata: role === undefined ? null : { "agent-access": { role } },
  }));
  for (const name of external) packages.push({ name, id: `registry+https://example.test#${name}@1.0.0`, metadata: null });
  const nodes = packages.map((pkg) => ({
    id: pkg.id,
    deps: (edges[pkg.name] ?? []).map(([dependency, ...kinds]) => ({
      pkg: roles[dependency] === undefined && external.includes(dependency)
        ? `registry+https://example.test#${dependency}@1.0.0` : id(dependency),
      dep_kinds: kinds.map((kind) => ({ kind, target: null })),
    })),
  }));
  return { packages, workspace_members: Object.keys(roles).map(id), resolve: { nodes } };
}

const baseRoles = {
  "agent-access-provider": "sdk",
  "agent-access-core": "core",
  "agent-access-broker-host": "host",
  "agent-access-broker": "assembly",
  "agent-access": "cli",
  "agent-access-jira": "native",
  "agent-access-conformance": "reference",
  "agent-access-mcp-upstream": "adapter",
  "agent-access-content": "helper",
};

const baseEdges = {
  "agent-access-core": [["agent-access-provider", null], ["agent-access-jira", "dev"]],
  "agent-access-broker-host": [["agent-access-core", null, "dev"], ["agent-access-provider", null],
    ["agent-access-jira", "dev"], ["agent-access-conformance", "dev"], ["agent-access-mcp-upstream", "dev"]],
  "agent-access-broker": [["agent-access-broker-host", null], ["agent-access-jira", null], ["agent-access-mcp-upstream", null]],
  "agent-access": [["agent-access-core", null], ["agent-access-provider", null],
    ["agent-access-broker", "dev"], ["agent-access-broker-host", "dev"], ["agent-access-jira", "dev"]],
  "agent-access-jira": [["agent-access-provider", null], ["agent-access-content", null], ["serde", null]],
  "agent-access-conformance": [["agent-access-provider", null]],
  "agent-access-mcp-upstream": [["agent-access-provider", null], ["agent-access-core", null], ["agent-access-jira", "dev"]],
  "agent-access-content": [["agent-access-provider", null]],
};

const withEdge = (from, edge) => ({ ...baseEdges, [from]: [...(baseEdges[from] ?? []), edge] });

test("an allowed workspace passes and reports the CLI's production core dependency", () => {
  const result = checkCrateBoundaries(metadata(baseRoles, baseEdges, { external: ["serde"] }));
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.notes, ["agent-access (cli) production closure includes agent-access-core (core) (allowed)"]);
  assert.deepEqual(ROLES, ["sdk", "core", "host", "assembly", "cli", "native", "reference", "adapter", "helper"]);
});

test("every workspace member must declare a known role", () => {
  for (const role of [undefined, "plugin", ""]) {
    const result = checkCrateBoundaries(metadata({ ...baseRoles, "agent-access-teams": role }, baseEdges));
    assert.equal(result.errors.length, 1);
    assert.match(result.errors[0], /^agent-access-teams: missing or unknown \[package\.metadata\.agent-access\] role/);
  }
  const roleless = metadata(baseRoles, baseEdges);
  roleless.packages.find((pkg) => pkg.name === "agent-access-core").metadata = { other: { role: "core" } };
  assert.match(checkCrateBoundaries(roleless).errors[0], /^agent-access-core: missing or unknown/);
  const absent = metadata(baseRoles, baseEdges);
  absent.workspace_members.push(id("agent-access-ghost"));
  assert.match(checkCrateBoundaries(absent).errors[0], /agent-access-ghost.*missing from cargo metadata/);
  const unresolved = metadata(baseRoles, baseEdges);
  delete unresolved.resolve;
  assert.match(checkCrateBoundaries(unresolved).errors[0], /no resolved dependency graph/);
});

test("the SDK has no workspace edge of any kind", () => {
  for (const kind of [null, "build", "dev"]) {
    const result = checkCrateBoundaries(metadata(baseRoles, withEdge("agent-access-provider", ["agent-access-content", kind])));
    assert.equal(result.errors.length, 1);
    assert.match(result.errors[0], /^agent-access-provider \(sdk\) must have no workspace dependency; found (normal|build|dev) edge to agent-access-content \(helper\)$/);
  }
  const external = checkCrateBoundaries(metadata(baseRoles, withEdge("agent-access-provider", ["serde", null]), { external: ["serde"] }));
  assert.deepEqual(external.errors, []);
});

test("native, reference and helper crates reach no core, host, assembly, CLI or adapter crate", () => {
  const cases = [
    ["agent-access-jira", "agent-access-core", "dev"],
    ["agent-access-jira", "agent-access-mcp-upstream", null],
    ["agent-access-conformance", "agent-access-broker-host", "dev"],
    ["agent-access-conformance", "agent-access-core", null],
    ["agent-access-content", "agent-access-broker", "build"],
    ["agent-access-content", "agent-access", "dev"],
  ];
  for (const [from, to, kind] of cases) {
    const result = checkCrateBoundaries(metadata(baseRoles, withEdge(from, [to, kind])));
    assert.ok(result.errors.some((error) => error.startsWith(`${from} (${baseRoles[from]}) must not depend on ${baseRoles[to]} crates;`)
      && error.endsWith(`edge to ${to} (${baseRoles[to]})`)), `${from} -> ${to}: ${result.errors}`);
  }
  const helperEdge = checkCrateBoundaries(metadata(baseRoles, withEdge("agent-access-conformance", ["agent-access-content", null])));
  assert.deepEqual(helperEdge.errors, []);
});

test("adapter production edges reach only SDK, helper and core crates", () => {
  for (const [to, kind] of [["agent-access-jira", null], ["agent-access-conformance", "build"], ["agent-access-broker-host", null]]) {
    const result = checkCrateBoundaries(metadata(baseRoles, withEdge("agent-access-mcp-upstream", [to, kind])));
    assert.ok(result.errors.some((error) => error.startsWith("agent-access-mcp-upstream (adapter) production dependencies may reach only sdk, helper or core crates;")
      && error.includes(`edge to ${to}`)), `${to}: ${result.errors}`);
  }
  const helper = checkCrateBoundaries(metadata(baseRoles, withEdge("agent-access-mcp-upstream", ["agent-access-content", null])));
  assert.deepEqual(helper.errors, []);
});

test("core and host production closures exclude native, adapter and reference crates, including transitively", () => {
  const direct = checkCrateBoundaries(metadata(baseRoles, withEdge("agent-access-broker-host", ["agent-access-conformance", "build"])));
  assert.deepEqual(direct.errors, ["agent-access-broker-host (host) production closure must not include reference crates; found agent-access-conformance (reference)"]);
  // A helper outside the core and host closures may use a native crate.
  const unreachable = checkCrateBoundaries(metadata(baseRoles, withEdge("agent-access-content", ["agent-access-jira", null])));
  assert.deepEqual(unreachable.errors, []);
  const transitive = checkCrateBoundaries(metadata(baseRoles, {
    ...withEdge("agent-access-core", ["agent-access-content", null]),
    "agent-access-content": [["agent-access-provider", null], ["agent-access-jira", null]],
  }));
  for (const expected of [
    "agent-access-core (core) production closure must not include native crates; found agent-access-jira (native)",
    "agent-access-broker-host (host) production closure must not include native crates; found agent-access-jira (native)",
    "agent-access (cli) production closure must not include native crates; found agent-access-jira (native)",
  ]) assert.ok(transitive.errors.includes(expected), `${expected}: ${transitive.errors}`);
  const adapter = checkCrateBoundaries(metadata(baseRoles, withEdge("agent-access-core", ["agent-access-mcp-upstream", null])));
  assert.ok(adapter.errors.includes("agent-access-core (core) production closure must not include adapter crates; found agent-access-mcp-upstream (adapter)"));
});

test("dev edges stay outside production closures", () => {
  const result = checkCrateBoundaries(metadata(baseRoles, {
    ...withEdge("agent-access-core", ["agent-access-conformance", "dev"]),
    "agent-access-content": [["agent-access-provider", null], ["agent-access-jira", "dev"]],
  }));
  assert.ok(!result.errors.some((error) => error.includes("production closure")), `${result.errors}`);
});

test("the CLI production closure excludes host, assembly, native, adapter and reference crates", () => {
  for (const to of ["agent-access-broker-host", "agent-access-broker", "agent-access-jira", "agent-access-mcp-upstream", "agent-access-conformance"]) {
    const result = checkCrateBoundaries(metadata(baseRoles, {
      ...baseEdges,
      "agent-access": baseEdges["agent-access"].filter(([dependency]) => dependency !== to).concat([[to, null, "dev"]]),
    }));
    assert.ok(result.errors.includes(`agent-access (cli) production closure must not include ${baseRoles[to]} crates; found ${to} (${baseRoles[to]})`), `${to}: ${result.errors}`);
  }
});

test("provider-side crates must not use host-only credential attachment or presentation", () => {
  const sources = {
    "agent-access-jira": [
      { path: "crates/agent-access-jira/src/backend.rs", text: "fn send() {}\nlet request = host::authorize_host_request(builder, &auth);\n" },
      { path: "crates/agent-access-jira/src/client.rs", text: "let auth = credential.authorization_as(&host::token_as_basic(\"oauth2\"))?;\n" },
    ],
    "agent-access-conformance": [{ path: "crates/agent-access-conformance/tests/it.rs", text: "use agent_access_provider::host::{authorize_host_request};\nuse agent_access_provider::host::token_as_basic;\n" }],
    "agent-access-mcp-upstream": [{ path: "crates/agent-access-mcp-upstream/src/lib.rs", text: "// authorize_host_request_like and token_as_basic_like are other names\nfn presents() {}\n" }],
    "agent-access-content": [{ path: "crates/agent-access-content/src/lib.rs", text: "authorize_host_request(request, &authorization)\n" }],
    // Host-side crates may use them.
    "agent-access-core": [{ path: "crates/agent-access-core/src/runtime.rs", text: "host::authorize_host_request(builder, &auth)\nhost::token_as_basic(username)\n" }],
    "agent-access-broker-host": [{ path: "crates/agent-access-broker-host/src/handlers/gateway.rs", text: "authorize_host_request(builder, &auth)\n" }],
  };
  const errors = hostOnlyUseViolations(metadata(baseRoles), (pkg) => sources[pkg.name] ?? []);
  assert.deepEqual(HOST_ONLY_ITEMS, ["authorize_host_request", "token_as_basic"]);
  assert.deepEqual(errors, [
    "agent-access-conformance (reference) must not use host-only authorize_host_request; found at crates/agent-access-conformance/tests/it.rs:1",
    "agent-access-conformance (reference) must not use host-only token_as_basic; found at crates/agent-access-conformance/tests/it.rs:2",
    "agent-access-content (helper) must not use host-only authorize_host_request; found at crates/agent-access-content/src/lib.rs:1",
    "agent-access-jira (native) must not use host-only authorize_host_request; found at crates/agent-access-jira/src/backend.rs:2",
    "agent-access-jira (native) must not use host-only token_as_basic; found at crates/agent-access-jira/src/client.rs:1",
  ]);
});

test("only workspace members with fenced roles are scanned", () => {
  const read = [];
  hostOnlyUseViolations(metadata(baseRoles, {}, { external: ["serde"] }), (pkg) => {
    read.push(pkg.name);
    return [];
  });
  assert.deepEqual(read, ["agent-access-conformance", "agent-access-content", "agent-access-jira", "agent-access-mcp-upstream"]);
});
