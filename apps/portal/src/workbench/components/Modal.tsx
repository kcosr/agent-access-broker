import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent, ReactNode, RefObject } from "react";
import { createPortal } from "react-dom";
import { cx } from "../lib/cx";
import {
  OverlayScope,
  useFocusTrap,
  useLayer,
  useOverlayOwner,
} from "../lib/layers";
import { Button, IconButton } from "./Button";

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  /** sm 440px (confirmations, prompts), md 560px (default), lg 760px. */
  size?: "sm" | "md" | "lg" | undefined;
  children?: ReactNode;
  /** Sticky footer, right-aligned (put the primary action last). */
  footer?: ReactNode;
  /** Muted text at the left of the footer. */
  footerNote?: ReactNode;
  /** Extra header content (e.g. a Seg) between the title and the × button. */
  headerExtra?: ReactNode;
  /** Render the dialog as a <form>; footer submit buttons then submit it. */
  onSubmit?: ((e: FormEvent<HTMLFormElement>) => void) | undefined;
  /** Esc, scrim click and × close it (default true). Turn off while saving. */
  dismissible?: boolean | undefined;
  /** Close when the scrim is clicked (default true). */
  closeOnScrim?: boolean | undefined;
  initialFocusRef?: RefObject<HTMLElement | null> | undefined;
  /**
   * "alertdialog" for urgent interruptions that need a response
   * (ConfirmDialog uses it); the body then describes the dialog.
   */
  role?: "dialog" | "alertdialog" | undefined;
  className?: string | undefined;
}

/** Modal dialog: scrim, focus trap, sticky header/footer, scrolling body. */
export function Modal(props: ModalProps) {
  if (!props.open) return null;
  return <ModalSurface {...props} />;
}

function ModalSurface({
  onClose,
  title,
  description,
  size = "md",
  children,
  footer,
  footerNote,
  headerExtra,
  onSubmit,
  dismissible = true,
  closeOnScrim = true,
  initialFocusRef,
  role = "dialog",
  className,
}: ModalProps) {
  const box = useRef<HTMLElement | null>(null);
  const titleId = `wb-modal-${useId()}`;
  const descId = description ? `${titleId}-desc` : undefined;
  // An alert dialog is described by its message (the body).
  const bodyId = `${titleId}-body`;
  const describedBy =
    [descId, role === "alertdialog" && children ? bodyId : undefined]
      .filter(Boolean)
      .join(" ") || undefined;
  const dismiss = () => {
    if (dismissible) onClose();
  };
  const root = useRef<HTMLDivElement | null>(null);
  const layers = useLayer(true, dismiss, true, root);
  // The owner covers the scrim too, so ancestor overlays leave its clicks alone.
  const owner = useOverlayOwner(root);
  useFocusTrap(box, true, { initialFocus: initialFocusRef, owner, layers });

  const content = (
    <>
      <div className="wb-modal-head">
        <div className="wb-modal-titles">
          <h2 className="wb-modal-title" id={titleId}>
            {title}
          </h2>
          {description ? (
            <p className="wb-modal-desc" id={descId}>
              {description}
            </p>
          ) : null}
        </div>
        {headerExtra}
        <IconButton
          icon="x"
          label="Close"
          title="Close (Esc)"
          onClick={dismiss}
          disabled={!dismissible}
        />
      </div>
      <div className="wb-modal-body" id={bodyId}>
        {children}
      </div>
      {footer || footerNote ? (
        <div className="wb-modal-foot">
          {footerNote ? (
            <span className="wb-modal-foot-note">{footerNote}</span>
          ) : null}
          {footer}
        </div>
      ) : null}
    </>
  );

  const shared = {
    className: cx("wb-modal", size !== "md" && `wb-modal--${size}`, className),
    role,
    "aria-modal": true,
    "aria-labelledby": titleId,
    "aria-describedby": describedBy,
    tabIndex: -1,
  } as const;

  return createPortal(
    <OverlayScope layers={layers} owner={owner}>
      <div ref={root}>
        <div
          className="wb-scrim"
          aria-hidden="true"
          onClick={closeOnScrim ? dismiss : undefined}
        />
        {onSubmit ? (
          <form
            {...shared}
            ref={(el) => {
              box.current = el;
            }}
            onSubmit={(e) => {
              e.preventDefault();
              onSubmit(e);
            }}
            noValidate
          >
            {content}
          </form>
        ) : (
          <div
            {...shared}
            ref={(el) => {
              box.current = el;
            }}
          >
            {content}
          </div>
        )}
      </div>
    </OverlayScope>,
    document.body,
  );
}

export interface ConfirmDialogProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  /** What will happen; name the object. */
  children?: ReactNode;
  confirmLabel?: string | undefined;
  cancelLabel?: string | undefined;
  /** danger (default) focuses Cancel first; primary focuses the confirm button. */
  tone?: "danger" | "primary" | undefined;
  /** May return a promise: the dialog shows pending, closes on success, shows the error on failure. */
  onConfirm: () => void | Promise<unknown>;
}

/** The one confirmation pattern: small modal, async confirm with pending and error states. */
export function ConfirmDialog(props: ConfirmDialogProps) {
  if (!props.open) return null;
  return <ConfirmSurface {...props} />;
}

function ConfirmSurface({
  onClose,
  title,
  children,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  tone = "danger",
  onConfirm,
}: ConfirmDialogProps) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cancelRef = useRef<HTMLButtonElement | null>(null);
  const confirmRef = useRef<HTMLButtonElement | null>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const confirm = async () => {
    if (pending) return;
    setError(null);
    setPending(true);
    try {
      await onConfirm();
      if (mounted.current) onClose();
    } catch (e) {
      if (!mounted.current) return;
      setError(e instanceof Error ? e.message : String(e));
      setPending(false);
    }
  };

  return (
    <ModalSurface
      open
      onClose={onClose}
      title={title}
      role="alertdialog"
      size="sm"
      dismissible={!pending}
      initialFocusRef={tone === "danger" ? cancelRef : confirmRef}
      footer={
        <>
          <Button ref={cancelRef} onClick={onClose} disabled={pending}>
            {cancelLabel}
          </Button>
          <Button
            ref={confirmRef}
            variant={tone === "danger" ? "danger" : "primary"}
            pending={pending}
            onClick={() => void confirm()}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      {children}
      {error ? (
        <div className="wb-form-error" role="alert">
          {error}
        </div>
      ) : null}
    </ModalSurface>
  );
}
