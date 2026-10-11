import { AdminForm } from "../../components/admin-access";
// Small presentation pieces shared by the Catalog pages and dialogs.
import { Fragment, type ReactNode } from "react";
import { Modal } from "../../workbench";
import "./catalog.css";

/** The parts of an editor dialog; a frame decides how they are shown. */
export type EditorParts = {
  title: string;
  description?: ReactNode;
  body: ReactNode;
  footer: ReactNode;
  footerNote?: ReactNode;
  onSubmit: () => void;
  onClose: () => void;
  pending: boolean;
  size?: "sm" | "md" | "lg";
};

export type EditorFrame = (parts: EditorParts) => ReactNode;

/** Editors open as kit modals with a sticky footer; Esc and × are off while saving. */
export const modalFrame: EditorFrame = ({ title, description, body, footer, footerNote, onSubmit, onClose, pending, size = "lg" }) => (
  <Modal open title={title} description={description} size={size} onClose={onClose} dismissible={!pending} closeOnScrim={false} onSubmit={onSubmit} footer={footer} footerNote={footerNote}>
    {body}
  </Modal>
);

/** The same parts as a plain form (server rendering in unit tests). */
export const inlineFrame: EditorFrame = ({ title, body, footer, footerNote, onSubmit }) => (
  <AdminForm
    aria-label={title}
    onSubmit={(event) => {
      event.preventDefault();
      onSubmit();
    }}
  >
    <h2>{title}</h2>
    {body}
    {footerNote}
    {footer}
  </AdminForm>
);

/**
 * Descriptions from upstream definitions can be long: short ones render in
 * full, long or multi-line ones collapse to three lines with a toggle.
 */
export function LongText({ text, subject }: { text: string; subject: string }) {
  const value = text.trim();
  if (!value) return null;
  if (value.length <= 240 && !value.includes("\n")) return <p className="pt-catalog-desc">{value}</p>;
  return (
    <details className="pt-catalog-more">
      <summary>
        <span className="pt-catalog-more-preview" aria-hidden="true">
          {value}
        </span>
        <span className="pt-catalog-more-show wb-link">
          Show full description<span className="wb-sr-only"> for {subject}</span>
        </span>
        <span className="pt-catalog-more-hide wb-link">
          Hide description<span className="wb-sr-only"> for {subject}</span>
        </span>
      </summary>
      <p className="pt-catalog-desc">{value}</p>
    </details>
  );
}

/** A `·`-separated inline list that skips empty parts (works inside flex meta rows and plain text). */
export function MetaLine({ parts }: { parts: ReactNode[] }) {
  const shown = parts.filter((part) => part !== null && part !== undefined && part !== false && part !== "");
  return (
    <>
      {shown.map((part, index) => (
        <Fragment key={index}>
          {index > 0 ? (
            <>
              {" "}
              <span className="wb-sep">·</span>{" "}
            </>
          ) : null}
          {part}
        </Fragment>
      ))}
    </>
  );
}
