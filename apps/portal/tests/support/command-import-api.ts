// Management API fixtures for a command import of the reference command: the
// import list, its record and preview, discovery, acceptance and credential
// writes, plus the catalog reads the Catalog pages make. Each discovery and
// acceptance moves the import to the next queued state; requests are recorded.
import type { Page } from "@playwright/test";
import type { ImportChangeBlocked, ImportDefinition, ImportPreviewResult, ImportResourceTypeEffects } from "../../src/import-types";
import type { ResourceRecord, Session } from "../../src/types";
import { RESOURCE_TYPES } from "../../unit/resource-types.fixture";
import { COMMAND_RESOURCE_TYPES, commandDraft, commandImportList, commandPolicyService } from "../../unit/command-import.fixture";

export type CommandImportApi = {
  /** The import's current state, or none before a draft is created. */
  current: ImportPreviewResult | null;
  /** States the next discoveries publish, in order. */
  discoveries: ImportPreviewResult[];
  /** States the next acceptances publish, in order, with the effects they report. */
  acceptances: Array<{ result: ImportPreviewResult; effects?: ImportResourceTypeEffects }>;
  /** A refusal the next acceptance answers with instead, as `target` lists. */
  acceptBlocked: Partial<ImportChangeBlocked> | null;
  commandImports: string[];
  resources: ResourceRecord[];
  created: ImportDefinition[];
  accepted: Array<Record<string, unknown>>;
  credentials: Array<{ purpose: string; body: Record<string, unknown> }>;
  errors: string[];
};

const stamp = { createdAt: "2026-10-15T09:00:00Z", updatedAt: "2026-10-15T09:00:00Z", createdBy: "admin", updatedBy: "admin" };
const ttlPolicy = { defaultTtl: "1h", maxTtl: "8h", options: ["1h", "8h"] };

export const ADMIN_SESSION = {
  authenticated: true,
  principal: "admin",
  role: "admin",
  selfServiceEnabled: true,
  policyManagementServices: [],
  csrfHeader: "x-csrf-token",
  csrfToken: "fixture",
  loginOptions: { localPassword: { enabled: true } },
  tokenIssuancePolicy: { selfAgentInvoke: ttlPolicy, administered: { agentInvoke: ttlPolicy, userManage: ttlPolicy, admin: ttlPolicy } }
} as Session;

/** The record result the Broker returns for a mutation of the import. */
function recordResult(data: ImportPreviewResult) {
  const { scopedMcpWarnings: _warnings, preview: _preview, resourceTypeChanges: _changes, affectedGrants: _affected, affectedGrantsByAction: _byAction, ...record } = data;
  return record;
}

export async function mockCommandImportApi(page: Page, current: ImportPreviewResult | null = null): Promise<CommandImportApi> {
  const api: CommandImportApi = { current, discoveries: [], acceptances: [], acceptBlocked: null, commandImports: ["ticketing", "deploy-tools"], resources: [], created: [], accepted: [], credentials: [], errors: [] };
  page.on("pageerror", (error) => api.errors.push(error.message));
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const method = request.method();
    const service = /^\/v1\/admin\/imports\/ticketing(?:\/(.*))?$/.exec(pathname);
    const fail = (message: string, blocked: Partial<ImportChangeBlocked>) =>
      route.fulfill({ status: 400, json: { ok: false, decision: "deny", reasonCode: "input_invalid", requestId: "fixture", brokerRequestId: "fixture", operation: "imports", principal: "admin", target: { service: "ticketing", ...blocked }, error: { message } } });
    let result: unknown = [];
    if (pathname === "/v1/auth/session") result = ADMIN_SESSION;
    else if (pathname === "/v1/resource-types" || pathname === "/v1/me") {
      // Discovery routes: their body is the result itself, without an envelope.
      await route.fulfill({ json: pathname === "/v1/me" ? { principal: "admin", serviceLimits: [] } : { resourceTypes: [...RESOURCE_TYPES, ...COMMAND_RESOURCE_TYPES] } });
      return;
    } else if (pathname === "/v1/admin/imports" && method === "POST") {
      const definition = request.postDataJSON() as ImportDefinition;
      api.created.push(definition);
      api.current = commandDraft(definition);
      result = recordResult(api.current);
    } else if (pathname === "/v1/admin/imports") {
      result = { ...commandImportList(api.current ? [api.current] : [], api.commandImports) };
    } else if (service && api.current) {
      const tail = service[1] ?? "";
      if (tail === "discover") {
        api.current = api.discoveries.shift() ?? api.current;
        result = api.current;
      } else if (tail === "accept") {
        api.accepted.push(request.postDataJSON() as Record<string, unknown>);
        if (api.acceptBlocked) {
          await fail("input is invalid: the import change is blocked", api.acceptBlocked);
          return;
        }
        const next = api.acceptances.shift();
        if (next) api.current = next.result;
        result = { ...recordResult(api.current), ...(next?.effects ? { resourceTypeEffects: next.effects } : {}) };
      } else if (tail.startsWith("credentials/")) {
        api.credentials.push({ purpose: tail.slice("credentials/".length), body: request.postDataJSON() as Record<string, unknown> });
        result = recordResult(api.current);
      } else result = api.current;
    } else if (pathname === "/v1/admin/policy/catalog") {
      result = {
        services: api.current && api.current.service.actions.length ? [commandPolicyService(api.current)] : [],
        resources: api.resources,
        resourceGroups: [],
        executionContexts: { allowedValues: ["internal", "external"], defaultContext: "internal", contextRequired: false },
        subjects: { users: [], groups: [], anonymous: false }
      };
    } else if (pathname === "/v1/admin/policy/resources") result = api.resources;
    else if (pathname === "/v1/admin/policy/status") result = { policyGeneration: 1, writable: true, authority: "managed", counts: { active: 0, disabled: 0, deleted: 0 }, managementScope: { kind: "global" } };
    else if (pathname === "/v1/admin/config/status") result = { identityAuthority: "managed", policyAuthority: "managed", generation: 1, loadedAt: stamp.createdAt, configHash: "fixture" };
    else if (pathname.endsWith("/audit/options")) result = { services: [] };
    else if (pathname.endsWith("/audit/events")) result = { records: [], nextCursor: null };
    await route.fulfill({ json: { ok: true, result } });
  });
  return api;
}
