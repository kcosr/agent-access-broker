import { AdminButton } from "../../components/admin-access";
// Sets or rotates an imported service's token slot, or the administrator's own
// personal discovery token. A command import whose credential is a username and
// token also takes the username. The token lives only in this mounted field and
// is cleared as soon as it is submitted; saved tokens are never shown again.
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
  withUsername = false,
  noun,
  onClose,
  onSave,
  frame = modalFrame
}: {
  purpose: TokenPurpose;
  /** A token is already stored (the title says Rotate). */
  rotate: boolean;
  /** The credential is a username and token; the username is sent with the token. */
  withUsername?: boolean;
  /** What the slot holds: a command import's execution slot is a credential of its declared kind. */
  noun: "token" | "credential";
  onClose: () => void;
  onSave: (token: string, username?: string) => Promise<unknown>;
  frame?: EditorFrame;
}) {
  const [value, setValue] = useState("");
  const [username, setUsername] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempted, setAttempted] = useState(false);
  const missing = !value.trim();
  const missingUsername = withUsername && !username.trim();

  async function save() {
    setAttempted(true);
    if (missing || missingUsername) return;
    const token = value;
    setValue("");
    setPending(true);
    setError(null);
    try {
      await (withUsername ? onSave(token, username.trim()) : onSave(token));
      onClose();
    } catch (failure) {
      setError(errorMessage(failure));
      setPending(false);
    }
  }

  return frame({
    title: `${rotate ? "Rotate" : "Set"} ${purpose} ${noun}`,
    size: "sm",
    body: (
      <div className="wb-form-stack pt-catalog-form">
        {withUsername ? (
          <Field label="Username" hint="The upstream account the token belongs to." error={attempted && missingUsername && !pending ? "Enter the username." : undefined}>
            <Input autoComplete="off" spellCheck={false} maxLength={256} value={username} disabled={pending} onChange={(event) => setUsername(event.target.value)} />
          </Field>
        ) : null}
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
        <AdminButton type="submit" variant="primary" pending={pending} disabled={(missing || missingUsername) && !pending}>
          {noun === "credential" ? "Save credential" : "Save token"}
        </AdminButton>
      </>
    ),
    onSubmit: () => void save(),
    onClose,
    pending
  });
}
