// How MCP clients connect to the broker's HTTP MCP endpoint with an agent
// token (docs/mcp.md, "HTTP endpoint"). Every snippet reads the token from the
// AGENT_ACCESS_TOKEN environment variable, never its value.

/** The server name clients register; matches the documented client configuration. */
export const MCP_SERVER_NAME = "agent_access";
/** The environment variable clients read the token from. */
export const MCP_TOKEN_ENV = "AGENT_ACCESS_TOKEN";

export type McpClientId = "pi" | "opencode" | "claude" | "codex" | "cursor";

/** A client's one-line command, or (Cursor) its install link, and its configuration file. */
export type McpClient = { id: McpClientId; label: string; file: string; config: string } & ({ command: string } | { installLink: string });

/**
 * The lines that put the token in the environment: for macOS and Linux shells,
 * and for Windows PowerShell, where `setx` keeps it for new terminals and
 * `$env:` sets it in the current one. The only place the token value appears.
 */
export function tokenEnvironment(value: string): { unix: string; windows: string } {
  return {
    unix: `export ${MCP_TOKEN_ENV}=${value}`,
    windows: `setx ${MCP_TOKEN_ENV} ${value}; $env:${MCP_TOKEN_ENV} = "${value}"`
  };
}

/** Setup for each supported client; `url` is the broker's canonical `/mcp` endpoint. */
export function mcpClients(url: string): McpClient[] {
  return [
    {
      id: "pi",
      label: "Pi",
      command: `pi mcp add ${MCP_SERVER_NAME} --url ${url} --bearer-token-env-var ${MCP_TOKEN_ENV}`,
      file: "~/.pi/agent/mcp.json",
      config: `{
  "mcpServers": {
    "${MCP_SERVER_NAME}": {
      "url": "${url}",
      "headers": { "Authorization": "Bearer \${${MCP_TOKEN_ENV}}" }
    }
  }
}`
    },
    {
      id: "opencode",
      label: "OpenCode",
      command: `opencode mcp add ${MCP_SERVER_NAME} --url ${url} --header 'Authorization=Bearer {env:${MCP_TOKEN_ENV}}'`,
      file: "~/.config/opencode/opencode.json",
      config: `{
  "mcp": {
    "${MCP_SERVER_NAME}": {
      "type": "remote",
      "url": "${url}",
      "oauth": false,
      "headers": { "Authorization": "Bearer {env:${MCP_TOKEN_ENV}}" }
    }
  }
}`
    },
    {
      id: "claude",
      label: "Claude Code",
      command: `claude mcp add --scope user --transport http ${MCP_SERVER_NAME} ${url} --header 'Authorization: Bearer \${${MCP_TOKEN_ENV}}'`,
      file: ".mcp.json",
      config: `{
  "mcpServers": {
    "${MCP_SERVER_NAME}": {
      "type": "http",
      "url": "${url}",
      "headers": { "Authorization": "Bearer \${${MCP_TOKEN_ENV}}" }
    }
  }
}`
    },
    {
      id: "codex",
      label: "Codex",
      command: `codex mcp add ${MCP_SERVER_NAME} --url ${url} --bearer-token-env-var ${MCP_TOKEN_ENV}`,
      file: "~/.codex/config.toml",
      config: `[mcp_servers.${MCP_SERVER_NAME}]
url = "${url}"
bearer_token_env_var = "${MCP_TOKEN_ENV}"`
    },
    {
      id: "cursor",
      label: "Cursor",
      installLink: cursorInstallLink(url),
      file: "~/.cursor/mcp.json",
      config: `{
  "mcpServers": {
    "${MCP_SERVER_NAME}": {
      "url": "${url}",
      "headers": { "Authorization": "Bearer \${env:${MCP_TOKEN_ENV}}" }
    }
  }
}`
    }
  ];
}

/** Cursor's one-click install link (it opens Cursor desktop) for the same server as `~/.cursor/mcp.json`. */
function cursorInstallLink(url: string): string {
  const server = { url, headers: { Authorization: `Bearer \${env:${MCP_TOKEN_ENV}}` } };
  return `cursor://anysphere.cursor-deeplink/mcp/install?name=${MCP_SERVER_NAME}&config=${encodeURIComponent(btoa(JSON.stringify(server)))}`;
}
