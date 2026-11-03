import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, test, vi } from "vitest";
import type { CatalogService } from "../src/features/catalog/catalog-data";
import { LimitsTab } from "../src/features/catalog/service-limits";
import type { ImportPreviewResult } from "../src/import-types";
import { commandDraft } from "./command-import.fixture";

vi.mock("../src/app/session", () => ({ useSession: () => ({ session: { authenticated: true, role: "admin", principal: "admin" } }) }));

function service(): CatalogService {
  return {
    service: "jira", displayName: "Jira", origin: "builtin", surface: "invoke",
    catalog: {
      service: "jira", displayName: "Jira", surface: "invoke", actions: [], resourceScopes: {},
      configuredCredentialModes: [], lookupCredentialConfigured: false
    },
    imported: null, actionCount: 0, managerCount: 0,
    state: { key: "available", label: "Available", tone: "success", icon: "circle-check", reason: null }
  };
}

function render(value: CatalogService, data: ImportPreviewResult | null = null) {
  return renderToStaticMarkup(createElement(MemoryRouter, null,
    createElement(LimitsTab, { service: value, data, onEdit: () => {} })
  ));
}

describe("catalog shared service caps", () => {
  test("shows configured shared policy without personal credential authority or edit controls", () => {
    const value = service();
    value.catalog!.aggregateInvocationLimit = { requests: 200, windowSeconds: 60 };
    const html = render(value);
    expect(html).toContain("Shared service cap");
    expect(html).toContain("200 requests per 1m");
    expect(html).toContain("across all principals in this Broker process");
    expect(html).toContain("Broker TOML");
    expect(html).toContain("[limits.invocations.aggregate.jira]");
    expect(html).toContain("How many requests each principal may make to Jira");
    expect(html).not.toMatch(/<(input|select|textarea)\b/);
    expect(html).not.toContain("No shared cap");
  });

  test("distinguishes no configured cap from unavailable catalog policy", () => {
    const value = service();
    expect(render(value)).toContain("No shared cap");
    value.catalog = null;
    const html = render(value);
    expect(html).toContain("Policy unavailable");
    expect(html).not.toContain("No shared cap");
  });

  test.each(["command", "mcp_http", "openapi_http"])("keeps %s personal defaults separate from shared TOML policy", (adapterKind) => {
    const data = commandDraft();
    data.service.definition.adapterKind = adapterKind;
    data.service.definition.invocationLimit = { requests: 7, windowSeconds: 90 };
    const value = service();
    value.service = data.service.definition.service;
    value.displayName = data.service.definition.displayName;
    value.origin = "imported";
    value.imported = data.service;
    value.catalog!.service = value.service;
    value.catalog!.aggregateInvocationLimit = { requests: 300, windowSeconds: 60 };
    const html = render(value, data);
    expect(html).toContain("7 requests per 90s");
    expect(html).toContain("300 requests per 1m");
    expect(html).toContain("Edit in import configuration");
    expect(html).toContain("It applies to each principal per service");
    expect(html).toContain("[limits.invocations.aggregate.ticketing]");
    expect(html).not.toMatch(/<(input|select|textarea)\b/);
  });
});
