// The Token created dialog offers MCP client setup only for agent tokens, and
// only when the broker reports an HTTP MCP endpoint that accepts them.
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { McpSetup, tokenMcpUrl } from "../src/features/tokens/mcp-setup";

const MCP_URL = "https://broker.example.com/mcp";
const TOKEN = "aab_ai_synthetic-token-value";

describe("MCP setup after token issuance", () => {
  it("is offered only for agent tokens with an MCP endpoint", () => {
    const agent = { tokenClass: "agent_invoke" };
    expect(tokenMcpUrl(agent, { mcp: { url: MCP_URL } })).toBe(MCP_URL);
    expect(tokenMcpUrl(agent, { mcp: null })).toBeNull();
    // Management tokens open the dialog without agent token options.
    expect(tokenMcpUrl(agent, undefined)).toBeNull();
    for (const tokenClass of ["user_manage", "admin"]) {
      expect(tokenMcpUrl({ tokenClass }, { mcp: { url: MCP_URL } }), tokenClass).toBeNull();
    }
  });

  it("shows the endpoint, the token environment and the first client", () => {
    const markup = renderToStaticMarkup(createElement(McpSetup, { url: MCP_URL, token: TOKEN }));
    expect(markup).toContain("Connect an MCP client");
    expect(markup).toContain(`>${MCP_URL}<`);
    expect(markup).toContain(`export AGENT_ACCESS_TOKEN=${TOKEN}`);
    for (const client of ["Pi", "OpenCode", "Claude Code", "Codex", "Cursor"]) expect(markup).toContain(`>${client}</button>`);
    expect(markup).toContain("pi mcp add agent_access");
    expect(markup).toContain("~/.pi/agent/mcp.json");
    // The environment line is the only place the token appears.
    expect(markup.split(TOKEN)).toHaveLength(2);
  });

  it("renders for an internationalized endpoint URL", () => {
    const url = "https://例え.test/mcp";
    const markup = renderToStaticMarkup(createElement(McpSetup, { url, token: TOKEN }));
    expect(markup).toContain("Connect an MCP client");
    expect(markup).toContain(`>${url}<`);
  });
});
