// MCP client setup shown after issuing an agent token: snippets name the token's
// environment variable and never contain the token itself.
import { describe, expect, it } from "vitest";
import { MCP_SERVER_NAME, MCP_TOKEN_ENV, mcpClients, tokenEnvironment } from "../src/features/tokens/mcp-clients";

const MCP_URL = "https://broker.example.com/mcp";
const TOKEN = "aab_ai_synthetic-token-value";

function snippets(client: ReturnType<typeof mcpClients>[number]) {
  return ["command" in client ? client.command : client.installLink, client.config];
}

/** The server object in Cursor's install link (base64 of UTF-8 JSON). */
function cursorLinkServer(installLink: string) {
  const link = new URL(installLink);
  const bytes = Uint8Array.from(atob(link.searchParams.get("config")!), (char) => char.charCodeAt(0));
  return { link, server: JSON.parse(new TextDecoder().decode(bytes)) };
}

/** The server URL each configuration file names. */
function configuredUrl(client: ReturnType<typeof mcpClients>[number]): string {
  if (client.id === "codex") {
    const line = client.config.split("\n").find((item) => item.startsWith("url = "))!;
    // A TOML basic string; the JSON escapes used are valid TOML escapes.
    return JSON.parse(line.slice("url = ".length));
  }
  const config = JSON.parse(client.config);
  return (config.mcpServers ?? config.mcp).agent_access.url;
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
    const { link, server } = cursorLinkServer(cursor.installLink);
    expect(link.protocol).toBe("cursor:");
    expect(`${link.host}${link.pathname}`).toBe("anysphere.cursor-deeplink/mcp/install");
    expect(link.searchParams.get("name")).toBe("agent_access");
    expect(server).toEqual({ url: MCP_URL, headers: { Authorization: "Bearer ${env:AGENT_ACCESS_TOKEN}" } });
    expect(server).toEqual(JSON.parse(cursor.config).mcpServers.agent_access);
    // Base64 padding and `+`/`/` are percent-encoded inside the query value.
    expect(cursor.installLink).not.toMatch(/config=[^&]*[=+/]/);
  });
});

describe("MCP client snippets for unusual URLs", () => {
  // The broker reports its parsed URL, but the snippets must stay valid and
  // building them must not throw whatever URL arrives.
  const urls = [
    "https://例え.test/mcp",
    "https://xn--r8jz45g.test/mcp",
    `https://broker.example.com/mcp?q="quoted" \\path'single'\u2028\u0007&x=1`
  ];

  it.each(urls)("stay parseable for %s", (url) => {
    const clients = mcpClients(url);
    expect(clients).toHaveLength(5);
    for (const client of clients) {
      expect(configuredUrl(client), client.id).toBe(url);
      if ("installLink" in client) {
        const { server } = cursorLinkServer(client.installLink);
        expect(server.url).toBe(url);
        expect(server).toEqual(JSON.parse(client.config).mcpServers.agent_access);
      }
    }
  });

  it("quote the URL as one shell word only when it needs quoting", () => {
    const command = (url: string) => {
      const pi = mcpClients(url).find((client) => client.id === "pi")!;
      return "command" in pi ? pi.command : "";
    };
    expect(command(MCP_URL)).toBe(`pi mcp add agent_access --url ${MCP_URL} --bearer-token-env-var AGENT_ACCESS_TOKEN`);
    expect(command("http://[::1]:4321/mcp")).toContain(" --url 'http://[::1]:4321/mcp' ");
    expect(command("https://broker.example.com/it's")).toContain(` --url 'https://broker.example.com/it'\\''s' `);
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
