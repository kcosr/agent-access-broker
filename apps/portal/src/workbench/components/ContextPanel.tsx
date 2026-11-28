import { useId } from "react";
import type { ReactNode } from "react";
import { cx } from "../lib/cx";
import { IconButton } from "./Button";
import { Modal } from "./Modal";

export interface ContextPanelProps {
  id?: string | undefined;
  title: ReactNode;
  open: boolean;
  onClose: () => void;
  /** Reserve space beside the page; otherwise open a modal sheet. */
  inline: boolean;
  children?: ReactNode;
  footer?: ReactNode;
  className?: string | undefined;
}

/**
 * Supporting page context: a passive card beside the content when space
 * permits, or a focus-trapped dialog on smaller layouts. The caller owns
 * the trigger, open state and layout breakpoint. Opening an inline card
 * never moves focus; after closing it, the caller can focus its trigger.
 */
export function ContextPanel({
  id,
  title,
  open,
  onClose,
  inline,
  children,
  footer,
  className,
}: ContextPanelProps) {
  const titleId = `wb-context-${useId()}`;
  if (!open) return null;
  if (!inline) {
    return (
      <Modal
        id={id}
        open
        onClose={onClose}
        title={title}
        size="sm"
        className={cx("wb-context-panel--overlay", className)}
        footer={footer}
      >
        {children}
      </Modal>
    );
  }
  return (
    <aside
      id={id}
      aria-labelledby={titleId}
      className={cx("wb-context-panel", className)}
    >
      <div className="wb-context-panel-head">
        <h2 id={titleId}>{title}</h2>
        <IconButton icon="x" label="Close" onClick={onClose} />
      </div>
      <div className="wb-context-panel-body">{children}</div>
      {footer ? <div className="wb-context-panel-foot">{footer}</div> : null}
    </aside>
  );
}
