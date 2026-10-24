import { AdminButton } from "../../components/admin-access";
import { useState } from "react";
import type { ImportCredentialInput, ImportPurpose } from "../../import-types";
import { errorMessage } from "../../lib/helpers";
import { importCredentialReady, importCredentialValues } from "../../lib/import-credentials";
import { Banner, Button } from "../../workbench";
import { FormError } from "../../components/form";
import { CredentialFields } from "../../components/credential-fields";
import { modalFrame, type EditorFrame } from "./catalog-ui";

export type TokenPurpose = ImportPurpose | "personal";

/** A slot's Broker-derived contract is the sole authority for its input fields. */
export function ImportTokenModal({ purpose, rotate, descriptor, noun, onClose, onSave, frame = modalFrame }: {
  purpose: TokenPurpose;
  rotate: boolean;
  descriptor: ImportCredentialInput;
  noun: "token" | "credential";
  onClose: () => void;
  onSave: (token: string, username?: string) => Promise<unknown>;
  frame?: EditorFrame;
}) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = descriptor.state === "ready" && importCredentialReady(descriptor, values);

  async function save() {
    if (descriptor.state !== "ready" || !ready) return;
    const { token = "", username } = importCredentialValues(descriptor, values);
    setValues({});
    setPending(true);
    setError(null);
    try {
      await onSave(token, username);
      onClose();
    } catch (failure) {
      setError(errorMessage(failure));
      setPending(false);
    }
  }

  return frame({
    title: `${rotate ? "Rotate" : "Set"} ${purpose} ${noun}`,
    size: "sm",
    body: <div className="wb-form-stack pt-catalog-form">
      {descriptor.state === "ready" ? <CredentialFields descriptor={descriptor} values={values} onChange={setValues} disabled={pending} /> : <Banner tone="warning" slim>{descriptor.reason}</Banner>}
      <FormError error={error} />
    </div>,
    footer: <>
      <Button onClick={onClose} disabled={pending}>Cancel</Button>
      <AdminButton type="submit" variant="primary" pending={pending} disabled={!ready}>{noun === "credential" ? "Save credential" : "Save token"}</AdminButton>
    </>,
    onSubmit: () => void save(), onClose, pending
  });
}
