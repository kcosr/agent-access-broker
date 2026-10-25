import { describe, expect, test } from "vitest";
import { IMPORT_DOCUMENT_MAX_BYTES, readOpenApiDocumentFile } from "../src/lib/import-document";

describe("local OpenAPI document feedback", () => {
  test("keeps the original bytes, including Unicode, whitespace and duplicate members for Broker validation", async () => {
    const bytes = '\n { "swagger": "2.0", "info": {"title":"café", "title":"second"}, "paths": {} }\n';
    const file = new File([bytes], "inventory.json", { type: "application/json" });
    const selected = await readOpenApiDocumentFile(file);
    expect(selected).toEqual({ file, protocolVersion: "2.0", label: "Swagger 2.0" });
    expect(selected.file).toBe(file);
    expect(await selected.file.text()).toBe(bytes);
  });
  test("uses byte size and admits the exact 4 MiB boundary", async () => {
    const prefix = '{"openapi":"3.1.0","note":"é';
    const suffix = '"}';
    const remaining = IMPORT_DOCUMENT_MAX_BYTES - new TextEncoder().encode(prefix + suffix).length;
    const file = new File([prefix, "x".repeat(remaining), suffix], "api.json");
    expect(file.size).toBe(IMPORT_DOCUMENT_MAX_BYTES);
    await expect(readOpenApiDocumentFile(file)).resolves.toMatchObject({ label: "OpenAPI 3.1.0" });
    await expect(readOpenApiDocumentFile(new File([file, " "], "api.json"))).rejects.toThrow("no larger than 4 MiB");
  });
  test.each(["{", "swagger: 2.0", new Uint8Array([0xff, 0xfe, 0x7b]), '\ufeff{"swagger":"2.0"}'])("refuses invalid JSON and UTF-8 before mutation", async (bytes) => {
    await expect(readOpenApiDocumentFile(new File([bytes], "api.json"))).rejects.toThrow("valid UTF-8 JSON");
  });
  test.each([{}, [], null, { swagger: 2 }, { swagger: "2.0", openapi: "3.1.0" }, { openapi: "3.0.3" }, { openapi: "3.1" }])("requires one supported source marker: %j", async (document) => {
    await expect(readOpenApiDocumentFile(new File([JSON.stringify(document)], "api.json"))).rejects.toThrow("Swagger 2.0 or OpenAPI 3.1");
  });
  test.each(["", ".", "..", "dir/api.json", "dir\\api.json", "bad\nname.json", "é".repeat(128)])("rejects unsafe or oversized filename %j", async (name) => {
    await expect(readOpenApiDocumentFile(new File(['{"swagger":"2.0"}'], name))).rejects.toThrow("filename");
  });
  test("admits a Unicode filename at the byte boundary", async () => {
    await expect(readOpenApiDocumentFile(new File(['{"swagger":"2.0"}'], "é".repeat(125) + ".json"))).resolves.toMatchObject({ protocolVersion: "2.0" });
  });
});
