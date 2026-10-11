import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (name) => readFileSync(new URL(`../${name}`, import.meta.url), "utf8");
const fields = (block) => Object.fromEntries([...block.matchAll(/^\s*(header|scheme)\s*=\s*"([^"]+)"/gm)].map((match) => [match[1], match[2]]));
const expectedIdentity = { header: "Authorization", scheme: "Bearer" };

test("authenticated CLI and MCP examples match the shipped Broker identity headers", () => {
  const client = read("agent-access.sample.toml").match(/^\[identity\]\n([^]*?)(?=^\[|$(?![^]))/m)?.[1];
  assert.ok(client, "CLI sample has an identity block");
  assert.deepEqual(fields(client), expectedIdentity);
  assert.match(client, /^disabled = true$/m, "default local sample remains anonymous");
  const mcpBlocks = [...read("docs/mcp.md").matchAll(/```toml\n([^]*?)\n```/g)]
    .map((match) => match[1]).filter((block) => /^\[identity\]$/m.test(block));
  assert.ok(mcpBlocks.length > 0, "MCP documentation includes authenticated client configuration");
  for (const block of mcpBlocks) assert.deepEqual(fields(block), expectedIdentity);
  for (const name of ["agent-access-broker.sample.toml", "agent-access-broker.production.sample.toml"]) {
    const source = read(name).replace(/^# ?/gm, "");
    const sources = [...source.matchAll(/^\[\[identity.sources\]\]\n([^]*?)(?=^\[|$(?![^]))/gm)];
    assert.ok(sources.length > 0, `${name} contains identity source examples`);
    for (const [, block] of sources) assert.deepEqual(fields(block), expectedIdentity, name);
  }
});

test("environment-only MCP example sets and forwards the paired Broker identity settings", () => {
  const docs = read("docs/mcp.md");
  const environmentBlocks = [...docs.matchAll(/```bash\n([^]*?)\n```/g)]
    .map((match) => match[1]).filter((block) => /^export AGENT_ACCESS_URL=/m.test(block));
  assert.equal(environmentBlocks.length, 1, "MCP documentation sets the client launch environment");
  const environment = Object.fromEntries([...environmentBlocks[0].matchAll(/^export (AGENT_ACCESS_[A-Z_]+)="([^"]+)"$/gm)]
    .map((match) => [match[1], match[2]]));
  assert.ok(environment.AGENT_ACCESS_URL, "broker URL is set");
  assert.ok(environment.AGENT_ACCESS_TOKEN_FILE, "token file is set");
  assert.deepEqual({
    header: environment.AGENT_ACCESS_IDENTITY_HEADER,
    scheme: environment.AGENT_ACCESS_IDENTITY_SCHEME,
  }, expectedIdentity);

  const forwardingBlocks = [...docs.matchAll(/```toml\n([^]*?)\n```/g)]
    .map((match) => match[1]).filter((block) => /^env_vars\s*=/m.test(block));
  assert.equal(forwardingBlocks.length, 1, "MCP documentation forwards the launch environment");
  const forwarded = [...forwardingBlocks[0].match(/env_vars\s*=\s*\[([^\]]*)\]/)[1].matchAll(/"([A-Z_]+)"/g)]
    .map((match) => match[1]);
  assert.deepEqual(forwarded.sort(), Object.keys(environment).sort(), "every configured variable reaches the MCP subprocess");
});
