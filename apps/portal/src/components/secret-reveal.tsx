// One-time secret dialogs: a newly issued token or a generated password. They
// close only through their buttons so a stray Esc or click cannot lose the secret.
import { useState, type ReactNode } from "react";
import { Banner, Button, Modal } from "../workbench";

export function SecretRevealModal({
  title,
  secretLabel,
  secret,
  details,
  onClose
}: {
  title: string;
  secretLabel: string;
  secret: string;
  details?: ReactNode;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <Modal
      open
      title={title}
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
      <div className="pt-form">
        <Banner tone="warning" slim>
          Copy this {secretLabel.toLowerCase()} now. It cannot be shown again after you close this dialog.
        </Banner>
        {details}
        <pre className="wb-code pt-reveal" aria-label={secretLabel}>
          {secret}
        </pre>
      </div>
    </Modal>
  );
}
