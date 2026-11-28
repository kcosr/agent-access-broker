// One-time secret dialogs: a newly issued token or a generated password. They
// close only through their buttons so a stray Esc or click cannot lose the secret.
// `children` follow the secret, such as how to use it.
import { useRef, useState, type ReactNode, type Ref } from "react";
import { Banner, Button, isMac, Modal } from "../workbench";

/** What a refused clipboard write leaves to the person: the secret is selected. */
const MANUAL_COPY = `Press ${isMac ? "⌘C" : "Ctrl+C"} to copy`;

export function SecretRevealModal({
  title,
  secretLabel,
  secret,
  details,
  size,
  children,
  onClose
}: {
  title: string;
  secretLabel: string;
  secret: string;
  details?: ReactNode;
  /** Wider ("lg") for long content after the secret. */
  size?: "md" | "lg";
  children?: ReactNode;
  onClose: () => void;
}) {
  const [copy, setCopy] = useState<"idle" | "copied" | "manual">("idle");
  const secretRef = useRef<HTMLPreElement>(null);
  function copySecret() {
    // Without the Clipboard API, or when the browser refuses, select the
    // secret so the person copies it by hand, and say how.
    const manual = () => {
      const element = secretRef.current;
      if (element) {
        element.focus({ preventScroll: true });
        element.ownerDocument.defaultView?.getSelection()?.selectAllChildren(element);
      }
      setCopy("manual");
    };
    let write: Promise<void>;
    try {
      write = navigator.clipboard.writeText(secret);
    } catch {
      manual();
      return;
    }
    write.then(() => setCopy("copied"), manual);
  }
  const copied = copy === "copied";
  return (
    <Modal
      open
      title={title}
      size={size}
      onClose={onClose}
      dismissible={false}
      closeOnScrim={false}
      footer={
        <>
          <span className="wb-small wb-muted" role="status" aria-live="polite">
            {copied ? "Copied" : copy === "manual" ? MANUAL_COPY : ""}
          </span>
          <Button icon={copied ? "check" : "copy"} onClick={copySecret}>
            {copied ? "Copied" : `Copy ${secretLabel.toLowerCase()}`}
          </Button>
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </>
      }
    >
      <SecretRevealBody secretLabel={secretLabel} secret={secret} details={details} secretRef={secretRef}>
        {children}
      </SecretRevealBody>
    </Modal>
  );
}

/** The dialog body: the warning, details, the secret, then `children`. */
export function SecretRevealBody({
  secretLabel,
  secret,
  details,
  secretRef,
  children
}: {
  secretLabel: string;
  secret: string;
  details?: ReactNode;
  secretRef?: Ref<HTMLPreElement>;
  children?: ReactNode;
}) {
  return (
    <div className="wb-form-stack">
      <Banner tone="warning" slim>
        Copy this {secretLabel.toLowerCase()} now. It cannot be shown again after you close this dialog.
      </Banner>
      {details}
      {/* Focusable, so the keyboard can scroll and select it. */}
      <pre ref={secretRef} className="wb-code pt-reveal" aria-label={secretLabel} tabIndex={0}>
        {secret}
      </pre>
      {children}
    </div>
  );
}
