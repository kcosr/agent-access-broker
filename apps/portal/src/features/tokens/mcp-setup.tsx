// "Connect an MCP client" in the Token created dialog: the broker's HTTP MCP
// endpoint, the line that puts the new token in the environment, and setup
// for each supported client. Only the environment line carries the token.
// The section is optional help: if it cannot be built or rendered it is left
// out, and the one-time token around it is unaffected.
import { Component, useId, useMemo, useState, type ReactNode } from "react";
import type { AgentTokenOptions, BrokerTokenRecord } from "../../types";
import { buttonClass, CopyBlock, readStorage, Seg, Tabs, writeStorage } from "../../workbench";
import { MCP_TOKEN_ENV, mcpClients, tokenEnvironment, type McpClient, type McpClientId } from "./mcp-clients";

/** The last chosen client (never the token), kept for the next issued token. */
export const MCP_CLIENT_KEY = "aab.portal.mcp-client";

const SYSTEMS = { unix: "macOS, Linux", windows: "Windows PowerShell" } as const;
type System = keyof typeof SYSTEMS;

type Snippets = { clients: McpClient[]; environment: Record<System, string> };

/**
 * The MCP endpoint to offer after issuing this token: agent tokens only, when
 * the broker reports an endpoint that accepts them; otherwise null.
 */
export function tokenMcpUrl(record: Pick<BrokerTokenRecord, "tokenClass">, options: Pick<AgentTokenOptions, "mcp"> | null | undefined): string | null {
  return record.tokenClass === "agent_invoke" ? (options?.mcp?.url ?? null) : null;
}

/** Every client's setup and the environment lines, or null when they cannot be built. */
function buildSnippets(url: string, token: string): Snippets | null {
  try {
    const clients = mcpClients(url);
    return clients.length ? { clients, environment: tokenEnvironment(token) } : null;
  } catch {
    return null;
  }
}

/** Hides the section, rather than the dialog, if it fails to render. */
class HideOnError extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    return this.state.failed ? null : this.props.children;
  }
}

export function McpSetup({ url, token }: { url: string; token: string }) {
  return (
    <HideOnError>
      <McpSetupSnippets url={url} token={token} />
    </HideOnError>
  );
}

function McpSetupSnippets({ url, token }: { url: string; token: string }) {
  const snippets = useMemo(() => buildSnippets(url, token), [url, token]);
  return snippets ? <McpSetupSection url={url} snippets={snippets} /> : null;
}

function storedClient(clients: McpClient[]): McpClientId {
  const stored = readStorage(MCP_CLIENT_KEY);
  return clients.find((client) => client.id === stored)?.id ?? clients[0].id;
}

function McpSetupSection({ url, snippets: { clients, environment } }: { url: string; snippets: Snippets }) {
  const heading = useId();
  const [system, setSystem] = useState<System>("unix");
  const [clientId, setClientId] = useState(() => storedClient(clients));
  const client = clients.find((item) => item.id === clientId) ?? clients[0];
  const chooseClient = (id: McpClientId) => {
    setClientId(id);
    writeStorage(MCP_CLIENT_KEY, id);
  };
  return (
    <section className="pt-mcp" aria-labelledby={heading}>
      <h3 id={heading} className="pt-section-title">
        Connect an MCP client
      </h3>
      <p className="pt-prose">
        Clients send the token as a Bearer credential from the <span className="wb-mono">{MCP_TOKEN_ENV}</span> environment variable. The commands and
        configuration below refer only to that variable.
      </p>
      <div className="pt-mcp-item">
        <span className="pt-mcp-label">Server URL</span>
        <CopyBlock wrap text={url} label="Copy server URL" />
      </div>
      <div className="pt-mcp-item">
        <div className="pt-mcp-head">
          <span className="pt-mcp-label">Token in your environment</span>
          <Seg
            label="Operating system"
            size="sm"
            value={system}
            onChange={setSystem}
            options={(Object.keys(SYSTEMS) as System[]).map((value) => ({ value, label: SYSTEMS[value] }))}
          />
        </div>
        <CopyBlock wrap text={environment[system]} label={`Copy the ${SYSTEMS[system]} line`} />
      </div>
      <div className="pt-mcp-item">
        <span className="pt-mcp-label">Your client</span>
        <Tabs label="MCP client" value={client.id} onChange={chooseClient} items={clients.map((item) => ({ value: item.id, label: item.label }))} panelClassName="pt-mcp-client">
          {"installLink" in client ? (
            <div>
              <a className={buttonClass({ variant: "primary" })} href={client.installLink}>
                Add to {client.label}
              </a>
            </div>
          ) : (
            <div className="pt-mcp-item">
              <span className="pt-mcp-label">Command</span>
              <CopyBlock wrap text={client.command} label={`Copy the ${client.label} command`} />
            </div>
          )}
          <div className="pt-mcp-item">
            <span className="pt-mcp-label">
              Or add it to <span className="wb-mono">{client.file}</span>
            </span>
            <CopyBlock multiline wrap text={client.config} label={`Copy the ${client.label} config file`} />
          </div>
        </Tabs>
      </div>
    </section>
  );
}
