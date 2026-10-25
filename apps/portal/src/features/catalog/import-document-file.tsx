import { useEffect, useId, useRef, useState } from "react";
import type { ImportDocumentMetadata } from "../../import-types";
import { readOpenApiDocumentFile, type OpenApiDocumentFile } from "../../lib/import-document";
import { errorMessage } from "../../lib/helpers";
import { FormError } from "../../components/form";
import { Button, Icon, Input, cx, formatBytes } from "../../workbench";

/** A chosen file remains local until its form is submitted, including across source-mode changes. */
export function useImportDocumentFile(initial: OpenApiDocumentFile | null = null) {
  const [selected, setSelected] = useState(initial);
  const [reading, setReading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const sequence = useRef(0);
  useEffect(() => () => { sequence.current++; }, []);

  async function select(files: readonly File[]) {
    if (!files.length) return;
    const current = ++sequence.current;
    setError(null);
    if (files.length !== 1) {
      setReading(false);
      setError("Choose one specification file.");
      return;
    }
    setReading(true);
    try {
      const value = await readOpenApiDocumentFile(files[0]!);
      if (current === sequence.current) setSelected(value);
    } catch (failure) {
      if (current === sequence.current) setError(errorMessage(failure));
    } finally {
      if (current === sequence.current) setReading(false);
    }
  }

  function remove() {
    sequence.current++;
    setSelected(null);
    setError(null);
    setReading(false);
  }

  return { selected, reading, error, select, remove };
}

export type ImportDocumentFileState = ReturnType<typeof useImportDocumentFile>;

/** Retained uploads expose only their safe filename and size, never their document contents. */
export function ImportDocumentSummary({ document }: { document: ImportDocumentMetadata }) {
  return <div className="pt-import-file-area has-file" aria-label="Stored definition document">
    <Icon name="file-text" />
    <div className="pt-import-file-content">
      <strong className="pt-catalog-break">{document.filename ?? "Uploaded JSON document"}</strong>
      <p className="pt-prose wb-small wb-muted">{formatBytes(document.byteLength)} · Stored by the Broker</p>
    </div>
  </div>;
}

/** Accessible browse control with drop support; all visual controls come from the shared kit. */
export function ImportDocumentFile({ value, disabled = false, missing = false }: {
  value: ImportDocumentFileState;
  disabled?: boolean;
  missing?: boolean;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const id = useId();
  const error = value.error ?? (missing && !value.selected ? "Choose a JSON specification file." : null);
  return (
    <div className="pt-import-file" role="group" aria-label="Specification file" aria-describedby={`${id}-help`} aria-busy={value.reading}>
      <Input
        ref={input}
        type="file"
        accept=".json,application/json"
        className="wb-sr-only"
        tabIndex={-1}
        aria-label="Choose specification JSON file"
        aria-describedby={`${id}-help`}
        aria-invalid={Boolean(error)}
        disabled={disabled}
        onChange={(event) => {
          void value.select(Array.from(event.target.files ?? []));
          event.target.value = "";
        }}
      />
      <div
        className={cx("pt-import-file-area", value.selected && "has-file", dragging && !disabled && "is-dragging")}
        onDragOver={(event) => {
          event.preventDefault();
          event.dataTransfer.dropEffect = disabled ? "none" : "copy";
          if (!disabled) setDragging(true);
        }}
        onDragLeave={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false);
        }}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          if (!disabled) void value.select(Array.from(event.dataTransfer.files));
        }}
      >
        <Icon name={value.selected ? "file-text" : "upload"} />
        <div className="pt-import-file-content">
          {value.selected ? (
            <>
              <strong className="pt-catalog-break">{value.selected.file.name}</strong>
              <p className="pt-prose wb-small wb-muted">{value.selected.label} · {formatBytes(value.selected.file.size)}</p>
            </>
          ) : <strong>Drop your specification here</strong>}
          <div className="wb-btn-group">
            <Button type="button" size="sm" pending={value.reading} disabled={disabled} onClick={() => input.current?.click()}>{value.selected ? "Replace file" : "Browse files…"}</Button>
            {value.selected ? <Button type="button" size="sm" variant="ghost" disabled={disabled} onClick={value.remove}>Remove</Button> : null}
          </div>
        </div>
      </div>
      <div id={`${id}-help`} className="pt-catalog-stack">
        <p className="pt-prose wb-small wb-muted">Swagger 2.0 or OpenAPI 3.1 JSON · Maximum 4 MiB</p>
        <p className="pt-prose wb-small wb-muted">No document URL or discovery credential needed. Upload a replacement to refresh later.</p>
      </div>
      <FormError error={error} />
    </div>
  );
}
