// How MCP clients connect to the broker's HTTP MCP endpoint with an agent
// token (docs/mcp.md, "HTTP endpoint"). Every snippet reads the token from the
// AGENT_ACCESS_TOKEN environment variable, never its value. Values are
// serialized, never spliced into JSON, TOML or shell syntax, so any URL yields
// valid snippets and building them cannot throw.

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

const bearer = (variable: string) => `Bearer ${variable}`;

/** A JSON configuration file, two-space indented. */
const json = (value: unknown) => JSON.stringify(value, null, 2);

/** A TOML basic string: JSON string escapes are valid TOML escapes. */
const tomlString = (value: string) => JSON.stringify(value);

/** One shell word: unchanged when plainly safe, otherwise single-quoted. */
function shellWord(value: string): string {
  return /^[A-Za-z0-9._~:/%+=,@-]+$/.test(value) ? value : `'${value.replaceAll("'", `'\\''`)}'`;
}

/** Setup for each supported client; `url` is the broker's canonical `/mcp` endpoint. */
export function mcpClients(url: string): McpClient[] {
  const shellUrl = shellWord(url);
  return [
    {
      id: "pi",
      label: "Pi",
      command: `pi mcp add ${MCP_SERVER_NAME} --url ${shellUrl} --bearer-token-env-var ${MCP_TOKEN_ENV}`,
      file: "~/.pi/agent/mcp.json",
      config: json({ mcpServers: { [MCP_SERVER_NAME]: { url, headers: { Authorization: bearer(`\${${MCP_TOKEN_ENV}}`) } } } })
    },
    {
      id: "opencode",
      label: "OpenCode",
      command: `opencode mcp add ${MCP_SERVER_NAME} --url ${shellUrl} --header 'Authorization=${bearer(`{env:${MCP_TOKEN_ENV}}`)}'`,
      file: "~/.config/opencode/opencode.json",
      config: json({ mcp: { [MCP_SERVER_NAME]: { type: "remote", url, oauth: false, headers: { Authorization: bearer(`{env:${MCP_TOKEN_ENV}}`) } } } })
    },
    {
      id: "claude",
      label: "Claude Code",
      command: `claude mcp add --scope user --transport http ${MCP_SERVER_NAME} ${shellUrl} --header 'Authorization: ${bearer(`\${${MCP_TOKEN_ENV}}`)}'`,
      file: ".mcp.json",
      config: json({ mcpServers: { [MCP_SERVER_NAME]: { type: "http", url, headers: { Authorization: bearer(`\${${MCP_TOKEN_ENV}}`) } } } })
    },
    {
      id: "codex",
      label: "Codex",
      command: `codex mcp add ${MCP_SERVER_NAME} --url ${shellUrl} --bearer-token-env-var ${MCP_TOKEN_ENV}`,
      file: "~/.codex/config.toml",
      config: `[mcp_servers.${MCP_SERVER_NAME}]\nurl = ${tomlString(url)}\nbearer_token_env_var = ${tomlString(MCP_TOKEN_ENV)}`
    },
    {
      id: "cursor",
      label: "Cursor",
      installLink: cursorInstallLink(url),
      file: "~/.cursor/mcp.json",
      config: json({ mcpServers: { [MCP_SERVER_NAME]: cursorServer(url) } })
    }
  ];
}

function cursorServer(url: string) {
  return { url, headers: { Authorization: bearer(`\${env:${MCP_TOKEN_ENV}}`) } };
}

/** Base64 of the text's UTF-8 bytes (`btoa` alone rejects characters above U+00FF). */
function base64Utf8(text: string): string {
  let binary = "";
  for (const byte of new TextEncoder().encode(text)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Cursor's one-click install link (it opens Cursor desktop) for the same server as `~/.cursor/mcp.json`. */
function cursorInstallLink(url: string): string {
  const config = base64Utf8(JSON.stringify(cursorServer(url)));
  return `cursor://anysphere.cursor-deeplink/mcp/install?name=${encodeURIComponent(MCP_SERVER_NAME)}&config=${encodeURIComponent(config)}`;
}
