import { useState, type ReactNode } from "react";
import type { ImportPreviewResult, ImportRecordResult } from "../../import-types";
import type { OpenApiDocumentFile } from "../../lib/import-document";
import { openApiDocumentSource } from "../../lib/import-openapi";
import { errorMessage } from "../../lib/helpers";
import { AdminButton } from "../../components/admin-access";
import { FormError } from "../../components/form";
import { Banner, Button } from "../../workbench";
import { ImportDocumentFile, ImportDocumentSummary, useImportDocumentFile } from "./import-document-file";
import { modalFrame, type EditorFrame } from "./catalog-ui";

/** Uploads create a normal discovery preview; accepting operations remains a separate decision. */
export function ImportDocumentModal({ data, initialFile, initialError, notice, replacement = false, closeLabel = "Cancel", onUpload, onReload, onUploaded, onClose, frame = modalFrame }: {
  data: ImportRecordResult;
  initialFile?: OpenApiDocumentFile;
  initialError?: string;
  notice?: ReactNode;
  replacement?: boolean;
  closeLabel?: string;
  onUpload: (file: File) => Promise<ImportPreviewResult>;
  onReload: () => Promise<void>;
  onUploaded: (result: ImportPreviewResult) => void;
  onClose: () => void;
  frame?: EditorFrame;
}) {
  const file = useImportDocumentFile(initialFile);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(initialError ?? null);
  const [needsReload, setNeedsReload] = useState(Boolean(initialError));
  const [reloaded, setReloaded] = useState(false);
  const uploaded = openApiDocumentSource(data.service.definition.connectionSettings) === "upload";
  const allowed = data.service.definition.adapterKind === "openapi_http" && uploaded && data.operatorAllowed && data.service.status !== "retired";
  const ready = file.selected && !file.reading && !file.error && allowed && !needsReload;
  async function reload() {
    setPending(true);
    try {
      await onReload();
      setNeedsReload(false);
      setReloaded(true);
      setError(null);
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setPending(false);
    }
  }
  async function upload() {
    if (!ready || pending) return;
    setPending(true);
    setError(null);
    try {
      const result = await onUpload(file.selected!.file);
      onUploaded(result);
    } catch (failure) {
      setError(errorMessage(failure));
      setNeedsReload(true);
      setReloaded(false);
      setPending(false);
    }
  }
  return frame({
    title: replacement ? "Upload replacement definition" : "Upload definition",
    body: <div className="wb-form-stack pt-catalog-form">
      {notice ? <Banner tone="warning" slim>{notice}</Banner> : null}
      {needsReload ? <Banner tone="warning" slim>The upload was not confirmed. Reload the current document and configuration before trying again.</Banner> : reloaded ? <Banner tone="info" slim>Current state reloaded. Review the document and configuration below before uploading.</Banner> : null}
      <div className="pt-catalog-stack" aria-label="Current import state">
        <p className="pt-prose wb-small">Definition source: {uploaded ? "Uploaded file" : "From URL"}. API security scheme: {data.service.definition.connectionSettings.securityScheme || "Not selected"}.</p>
        {data.service.document ? <ImportDocumentSummary document={data.service.document} /> : <p className="pt-prose wb-small wb-muted">No document is stored.</p>}
        <p className="pt-prose wb-small wb-muted">Service revision {data.service.version} · Catalog revision {data.catalogRevision}</p>
      </div>
      {!allowed ? <Banner tone="warning" slim>This service no longer permits document uploads. Open its Import tab to review the current configuration.</Banner> : null}
      <ImportDocumentFile value={file} disabled={pending} />
      <p className="pt-prose wb-small">The Broker validates the document and prepares operations for review. Changed or missing accepted operations are quarantined; existing grant action lists do not expand.</p>
      <FormError error={error} />
    </div>,
    footer: <>
      <Button onClick={onClose} disabled={pending}>{closeLabel}</Button>
      {needsReload ? <Button onClick={() => void reload()} disabled={pending}>Reload current state</Button> : null}
      <AdminButton type="submit" variant="primary" icon="upload" pending={pending} disabled={!ready}>Upload and review</AdminButton>
    </>,
    onSubmit: () => void upload(), onClose, pending
  });
}
