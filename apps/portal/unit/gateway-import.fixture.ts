// Presentation fixtures only. The backend compiler and real HTTP acceptance
// suite independently verify the document, policy and transport contracts.
import type { ImportActionDefinition, ImportGatewayBinding, ImportListResult, ImportPreviewResult } from "../src/import-types";
import type { PolicyServiceCatalog } from "../src/types";

export const GATEWAY_BINDING: ImportGatewayBinding = {
  service: "inventory", endpoint: "https://inventory.example.test/api", brokerHosts: ["inventory.gateway.example.test"],
  authModes: ["bearer_broker_token"], allowForwardedIdentity: false, available: true
};

export function gatewayOperation(action = "get_item", method = "GET", path = "/items/{id}"): ImportActionDefinition {
  return {
    action, source: { operationId: action }, label: "Inventory item", description: "Access an inventory item", readOnly: false,
    inputSchema: { type: "object", properties: { id: { type: "string" } } },
    annotations: {
      openapiGateway: {
        version: 1, method, path, security: { kind: "anonymous" },
        parameters: [{ name: "id", location: "path", required: true, style: "simple", explode: false, schema: { type: "string" } }],
        responses: { "200": { headers: [{ name: "X-Api-Version", schema: { type: "string", maxLength: 32 } }], contentTypes: ["application/json"] } }
      }
    }
  };
}

export function gatewayPreview(): ImportPreviewResult {
  return {
    catalogRevision: 4, operatorAllowed: true, available: true, scopedMcp: null, scopedMcpWarnings: [], importAuthentication: [], affectedGrants: [], affectedGrantsByAction: {},
    service: {
      definition: {
        service: "inventory", displayName: "Inventory gateway", adapterKind: "openapi_gateway", endpoint: GATEWAY_BINDING.endpoint,
        connectionSettings: { definitionSource: "upload", executionAuthentication: "anonymous" },
        executionBindings: [], discovery: { kind: "anonymous" }, transportAuth: false
      },
      status: "draft", version: 1, actions: [], slotVersions: {}, credentialInputs: {},
      document: { filename: "inventory.json", byteLength: 768, sha256: "a".repeat(64) },
      createdAt: "2026-11-07T00:00:00Z", updatedAt: "2026-11-07T00:00:00Z", createdBy: "admin", updatedBy: "admin"
    },
    preview: {
      service: "inventory", serviceVersion: 1, catalogRevision: 4, configRevision: "config", credentialVersions: {}, manifestHash: "manifest",
      createdAt: "2026-11-07T00:00:00Z", expiresAt: "2099-11-07T00:00:00Z", createdBy: "admin",
      manifest: {
        protocolVersion: "3.1.1", metadata: { bodyValidation: "none", securitySchemes: [{ name: "key", kind: "raw_header", header: "X-Api-Key" }, { name: "basic", kind: "basic" }, { name: "bearer", kind: "bearer" }] },
        tools: [{ definition: gatewayOperation(), unsupportedReason: null, readOnlyHint: null }]
      }
    }
  };
}

export function gatewayImportList(current?: ImportPreviewResult): ImportListResult {
  return {
    catalogRevision: current?.catalogRevision ?? 4, operatorEnabled: true, availableKinds: ["openapi_http", "openapi_gateway"], commandImports: [],
    gatewayBindings: [{ ...GATEWAY_BINDING, available: !current, ...(current ? { unavailableReason: "Service identity is already retained" } : {}) }],
    importAuthentication: [], services: current ? [current.service] : []
  };
}

export function gatewayPolicyService(current: ImportPreviewResult): PolicyServiceCatalog {
  return {
    service: current.service.definition.service, displayName: current.service.definition.displayName,
    surface: "gateway", gatewayKind: "openapi_gateway", brokerHosts: GATEWAY_BINDING.brokerHosts,
    credentialVerificationSupported: false, credentialVerificationInputs: [], available: current.available,
    actions: current.service.actions.map((record) => ({
      action: record.definition.action, description: record.definition.description, readOnly: record.definition.readOnly,
      requiredScopeTypes: [], credentialModes: ["service"], lookupRequired: false, inputSchema: record.definition.inputSchema,
      available: record.status === "enabled"
    })),
    resourceScopes: {}, configuredCredentialModes: ["service"], lookupCredentialConfigured: false
  };
}
