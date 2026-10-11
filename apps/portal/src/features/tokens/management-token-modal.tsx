// Issue a setup (user_manage) or admin token for a user's CLI.
import { useState } from "react";
import type { TokenTtlPolicy } from "../../types";
import { errorMessage } from "../../lib/helpers";
import { Button, Field, Input, KeyValue, Modal, Select } from "../../workbench";
import { FormError } from "../../components/form";

export function ManagementTokenModal({
  principalId,
  tokenClass,
  ttlPolicy,
  onClose,
  onIssue
}: {
  principalId: string;
  tokenClass: "user_manage" | "admin";
  ttlPolicy: TokenTtlPolicy;
  onClose: () => void;
  onIssue: (name: string, lifetime: string) => Promise<void>;
}) {
  const setup = tokenClass === "user_manage";
  const title = setup ? "Issue setup token" : "Issue admin token";
  const [name, setName] = useState("");
  const [lifetime, setLifetime] = useState(ttlPolicy.defaultTtl ?? ttlPolicy.options[0] ?? "");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal
      open
      title={title}
      onClose={onClose}
      dismissible={!pending}
      onSubmit={async () => {
        if (!name.trim() || !lifetime) return;
        setPending(true);
        setError(null);
        try {
          await onIssue(name, lifetime);
        } catch (failure) {
          setError(errorMessage(failure));
          setPending(false);
        }
      }}
      footer={
        <>
          <Button onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={!name.trim() || !lifetime} pending={pending}>
            {title}
          </Button>
        </>
      }
    >
      <div className="pt-form">
        <KeyValue
          items={[
            { label: "Principal", value: <span className="wb-num">{principalId}</span> },
            { label: "Token class", value: <span className="wb-num">{tokenClass}</span> },
            {
              label: "Authority",
              value: setup
                ? "Manages this principal's own credentials within granted rights and issues agent tokens."
                : "Calls admin management APIs while this principal stays active and keeps the admin role."
            }
          ]}
        />
        <Field label="Name">
          <Input value={name} onChange={(event) => setName(event.target.value)} required autoFocus />
        </Field>
        <Field label="Lifetime" hint={`Choices are configured by the broker. ${tokenClass} tokens always expire.`}>
          <Select value={lifetime} onChange={(event) => setLifetime(event.target.value)} options={ttlPolicy.options.map((option) => ({ value: option, label: option }))} />
        </Field>
        <FormError error={error} />
      </div>
    </Modal>
  );
}
