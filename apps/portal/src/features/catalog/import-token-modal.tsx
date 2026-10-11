import { AdminButton } from "../../components/admin-access";
// Sets or rotates an imported service's token slot, or the administrator's own
// personal discovery token. The value lives only in this mounted field and is
// cleared as soon as it is submitted; saved tokens are never shown again.
import { useState } from "react";
import type { ImportPurpose } from "../../import-types";
import { errorMessage } from "../../lib/helpers";
import { Button, Field, Input } from "../../workbench";
import { FormError } from "../../components/form";
import { modalFrame, type EditorFrame } from "./catalog-ui";

export type TokenPurpose = ImportPurpose | "personal";

export function ImportTokenModal({
  purpose,
  rotate,
  onClose,
  onSave,
  frame = modalFrame
}: {
  purpose: TokenPurpose;
  /** A token is already stored (the title says Rotate). */
  rotate: boolean;
  onClose: () => void;
  onSave: (token: string) => Promise<unknown>;
  frame?: EditorFrame;
}) {
  const [value, setValue] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempted, setAttempted] = useState(false);
  const missing = !value.trim();

  async function save() {
    setAttempted(true);
    if (missing) return;
    const token = value;
    setValue("");
    setPending(true);
    setError(null);
    try {
      await onSave(token);
      onClose();
    } catch (failure) {
      setError(errorMessage(failure));
      setPending(false);
    }
  }

  return frame({
    title: `${rotate ? "Rotate" : "Set"} ${purpose} token`,
    size: "sm",
    body: (
      <div className="pt-form pt-catalog-form">
        <Field
          label="Token"
          hint="Paste the token value without a Bearer prefix. Existing values cannot be revealed."
          error={attempted && missing && !pending ? "Enter the token." : undefined}
        >
          <Input type="password" autoComplete="new-password" spellCheck={false} value={value} disabled={pending} onChange={(event) => setValue(event.target.value)} />
        </Field>
        <FormError error={error} />
      </div>
    ),
    footer: (
      <>
        <Button onClick={onClose} disabled={pending}>
          Cancel
        </Button>
        <AdminButton type="submit" variant="primary" pending={pending} disabled={missing && !pending}>
          Save token
        </AdminButton>
      </>
    ),
    onSubmit: () => void save(),
    onClose,
    pending
  });
}
