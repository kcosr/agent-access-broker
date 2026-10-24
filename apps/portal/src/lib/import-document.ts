/** Local file checks improve feedback; the Broker validates the original bytes. */
export const IMPORT_DOCUMENT_MAX_BYTES = 4 * 1024 * 1024;

export type OpenApiDocumentFile = {
  file: File;
  protocolVersion: string;
  label: string;
};

export async function readOpenApiDocumentFile(file: File): Promise<OpenApiDocumentFile> {
  if (!file.name || /^\.+$/.test(file.name) || /[/\\\p{Cc}]/u.test(file.name) || new TextEncoder().encode(file.name).length > 255) {
    throw new Error("Use a filename of up to 255 UTF-8 bytes, without path separators or control characters.");
  }
  if (file.size > IMPORT_DOCUMENT_MAX_BYTES) throw new Error("Choose a JSON specification no larger than 4 MiB.");
  let document: unknown;
  try {
    const bytes = await file.arrayBuffer();
    // Keep the File itself for upload. Parsing must never re-encode or remove duplicate members.
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    document = JSON.parse(text);
  } catch {
    throw new Error("Choose a valid UTF-8 JSON specification.");
  }
  if (document && typeof document === "object" && !Array.isArray(document)) {
    const version = document as Record<string, unknown>;
    if (version.swagger === "2.0" && !Object.hasOwn(version, "openapi")) return { file, protocolVersion: "2.0", label: "Swagger 2.0" };
    if (typeof version.openapi === "string" && /^3\.1\.\d+$/.test(version.openapi) && !Object.hasOwn(version, "swagger")) {
      return { file, protocolVersion: version.openapi, label: `OpenAPI ${version.openapi}` };
    }
  }
  throw new Error("Choose a JSON document with a Swagger 2.0 or OpenAPI 3.1 version marker.");
}
