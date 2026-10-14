// MCP client setup is optional help in the one-time token dialog: if its
// snippets cannot be built, the section is left out and the token still shows.
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { SecretRevealBody } from "../src/components/secret-reveal";
import { McpSetup } from "../src/features/tokens/mcp-setup";

vi.mock("../src/features/tokens/mcp-clients", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/features/tokens/mcp-clients")>()),
  mcpClients: () => {
    throw new Error("snippet builder failed");
  }
}));

const TOKEN = "aab_ai_synthetic-token-value";

describe("a failing MCP setup", () => {
  it("leaves the token reveal intact and hides the section", () => {
    const markup = renderToStaticMarkup(
      createElement(SecretRevealBody, { secretLabel: "Token", secret: TOKEN }, createElement(McpSetup, { url: "https://broker.example.com/mcp", token: TOKEN }))
    );
    expect(markup).toContain(`aria-label="Token">${TOKEN}</pre>`);
    expect(markup).toContain("Copy this token now.");
    expect(markup).not.toContain("Connect an MCP client");
    expect(markup).not.toContain("AGENT_ACCESS_TOKEN");
  });
});
