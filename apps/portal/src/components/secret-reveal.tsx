// One-time secret dialogs: a newly issued token or a generated password. They
// close only through their buttons so a stray Esc or click cannot lose the secret.
// `children` follow the secret, such as how to use it.
import { useState, type ReactNode } from "react";
import { Banner, Button, Modal } from "../workbench";

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
  const [copied, setCopied] = useState(false);
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
          <Button
            icon={copied ? "check" : "copy"}
            onClick={() => {
              void navigator.clipboard?.writeText(secret).then(() => setCopied(true), () => undefined);
            }}
          >
            {copied ? "Copied" : `Copy ${secretLabel.toLowerCase()}`}
          </Button>
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </>
      }
    >
      <SecretRevealBody secretLabel={secretLabel} secret={secret} details={details}>
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
  children
}: {
  secretLabel: string;
  secret: string;
  details?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="wb-form-stack">
      <Banner tone="warning" slim>
        Copy this {secretLabel.toLowerCase()} now. It cannot be shown again after you close this dialog.
      </Banner>
      {details}
      <pre className="wb-code pt-reveal" aria-label={secretLabel}>
        {secret}
      </pre>
      {children}
    </div>
  );
}
