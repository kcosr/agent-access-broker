// MCP client setup shown after issuing an agent token: snippets name the token's
// environment variable and never contain the token itself.
import { describe, expect, it } from "vitest";
import { MCP_SERVER_NAME, MCP_TOKEN_ENV, mcpClients, tokenEnvironment } from "../src/features/tokens/mcp-clients";

const MCP_URL = "https://broker.example.com/mcp";
const TOKEN = "aab_ai_synthetic-token-value";

function snippets(client: ReturnType<typeof mcpClients>[number]) {
  return ["command" in client ? client.command : client.installLink, client.config];
}

describe("MCP client snippets", () => {
  it("cover exactly the supported clients", () => {
    expect(mcpClients(MCP_URL).map((client) => [client.id, client.label])).toEqual([
      ["pi", "Pi"],
      ["opencode", "OpenCode"],
      ["claude", "Claude Code"],
      ["codex", "Codex"],
      ["cursor", "Cursor"]
    ]);
  });

  it("name the server, URL and token variable, never a token value", () => {
    for (const client of mcpClients(MCP_URL)) {
      expect(client.config, client.id).toContain(MCP_URL);
      expect(client.config, client.id).toContain(MCP_SERVER_NAME);
      expect(client.config, client.id).toContain(MCP_TOKEN_ENV);
      if ("command" in client) {
        expect(client.command, client.id).toContain(MCP_URL);
        expect(client.command, client.id).toContain(MCP_SERVER_NAME);
        expect(client.command, client.id).toContain(MCP_TOKEN_ENV);
      }
      for (const snippet of snippets(client)) {
        expect(snippet, client.id).not.toContain(TOKEN);
        expect(snippet, client.id).not.toMatch(/aab_/);
      }
    }
  });

  it("match the documented Codex and Claude Code configuration", () => {
    const clients = Object.fromEntries(mcpClients(MCP_URL).map((client) => [client.id, client]));
    expect(clients.codex.config).toBe(`[mcp_servers.agent_access]\nurl = "${MCP_URL}"\nbearer_token_env_var = "AGENT_ACCESS_TOKEN"`);
    expect(JSON.parse(clients.claude.config)).toEqual({
      mcpServers: { agent_access: { type: "http", url: MCP_URL, headers: { Authorization: "Bearer ${AGENT_ACCESS_TOKEN}" } } }
    });
    expect("command" in clients.claude && clients.claude.command).toBe(
      `claude mcp add --scope user --transport http agent_access ${MCP_URL} --header 'Authorization: Bearer \${AGENT_ACCESS_TOKEN}'`
    );
  });

  it("keep every JSON configuration valid", () => {
    for (const client of mcpClients(MCP_URL).filter((item) => item.file.endsWith(".json"))) {
      expect(() => JSON.parse(client.config), client.id).not.toThrow();
    }
  });

  it("encode Cursor's install link as base64 JSON of the same server", () => {
    const cursor = mcpClients(MCP_URL).find((client) => client.id === "cursor")!;
    if (!("installLink" in cursor)) throw new Error("Cursor installs through a link");
    const link = new URL(cursor.installLink);
    expect(link.protocol).toBe("cursor:");
    expect(`${link.host}${link.pathname}`).toBe("anysphere.cursor-deeplink/mcp/install");
    expect(link.searchParams.get("name")).toBe("agent_access");
    const server = JSON.parse(atob(link.searchParams.get("config")!));
    expect(server).toEqual({ url: MCP_URL, headers: { Authorization: "Bearer ${env:AGENT_ACCESS_TOKEN}" } });
    expect(server).toEqual(JSON.parse(cursor.config).mcpServers.agent_access);
    // Base64 padding and `+`/`/` are percent-encoded inside the query value.
    expect(cursor.installLink).not.toMatch(/config=[^&]*[=+/]/);
  });
});

describe("token environment lines", () => {
  it("are the only place the token appears", () => {
    expect(tokenEnvironment(TOKEN)).toEqual({
      unix: `export AGENT_ACCESS_TOKEN=${TOKEN}`,
      windows: `setx AGENT_ACCESS_TOKEN ${TOKEN}; $env:AGENT_ACCESS_TOKEN = "${TOKEN}"`
    });
  });
});
