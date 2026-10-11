import { AdminIconButton } from "../../components/admin-access";
// Private resource attributes (for example a signed webhook URL). Revealed
// values stay in the mounted field's state, never in the query cache or the
// URL, and are dropped when the field unmounts or a save starts.
import { useEffect, useRef, useState } from "react";
import type { ResourceAttributeMetadata } from "../../types";
import { Field, Input } from "../../workbench";

/** Reveal and copy for a stored attribute value. */
function useReveal(label: string, busy: boolean, onReveal: () => Promise<string>) {
  const [revealed, setRevealed] = useState<string>();
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState("");
  const generation = useRef(0);
  useEffect(
    () => () => {
      generation.current += 1;
    },
    []
  );
  useEffect(() => {
    if (busy) {
      generation.current += 1;
      setRevealed(undefined);
      setLoading(false);
      setNotice("");
    }
  }, [busy]);

  async function reveal(copy = false) {
    const current = ++generation.current;
    setLoading(true);
    setNotice("");
    try {
      const secret = await onReveal();
      if (current !== generation.current) return;
      if (copy) {
        await navigator.clipboard.writeText(secret);
        if (current === generation.current) setNotice(`${label} copied.`);
      } else setRevealed(secret);
    } catch {
      if (current === generation.current) setNotice(`Could not ${copy ? "copy" : "reveal"} ${label.toLowerCase()}.`);
    } finally {
      if (current === generation.current) setLoading(false);
    }
  }

  function hide() {
    generation.current += 1;
    setRevealed(undefined);
  }

  return { revealed, loading, notice, reveal, hide };
}

/** The stored value, masked until revealed, with reveal/hide and copy. */
export function ResourceAttributeValue({
  field,
  busy = false,
  onReveal,
  label
}: {
  field: ResourceAttributeMetadata;
  busy?: boolean;
  onReveal: () => Promise<string>;
  label?: string;
}) {
  const state = useReveal(field.label, busy, onReveal);
  return (
    <Field label={label ?? `Current ${field.label}`}>
      <div className="pt-catalog-secret">
        <Input
          readOnly
          mono={state.revealed !== undefined}
          type={state.revealed === undefined ? "password" : "text"}
          value={state.revealed ?? "••••••••••••••••"}
          autoComplete="off"
          spellCheck={false}
        />
        <AdminIconButton
          variant="default"
          icon={state.revealed === undefined ? "eye" : "eye-off"}
          label={`${state.revealed === undefined ? "Reveal" : "Hide"} ${field.label}`}
          disabled={busy || state.loading}
          onClick={() => (state.revealed === undefined ? void state.reveal() : state.hide())}
        />
        <AdminIconButton variant="default" icon="copy" label={`Copy ${field.label}`} disabled={busy || state.loading} onClick={() => void state.reveal(true)} />
      </div>
      {state.notice ? (
        <p role="status" className="pt-prose wb-small">
          {state.notice}
        </p>
      ) : null}
    </Field>
  );
}

/** Editor field: the stored value (when configured) plus an optional replacement. */
export function ResourceAttributeField({
  field,
  configured,
  value,
  busy,
  onChange,
  onReveal
}: {
  field: ResourceAttributeMetadata;
  configured: boolean;
  value: string;
  busy: boolean;
  onChange: (value: string) => void;
  onReveal: () => Promise<string>;
}) {
  return (
    <div className="pt-form pt-catalog-form">
      {configured ? <ResourceAttributeValue field={field} busy={busy} onReveal={onReveal} /> : null}
      <Field
        label={configured ? `Replacement ${field.label}` : field.label}
        optional={configured}
        hint={
          <>
            {field.description}
            {configured ? " Leave the replacement blank to keep the current value." : null}
          </>
        }
      >
        <Input
          type="password"
          value={value}
          required={field.required && !configured}
          maxLength={8192}
          autoComplete="new-password"
          spellCheck={false}
          disabled={busy}
          onChange={(event) => onChange(event.target.value)}
        />
      </Field>
    </div>
  );
}
