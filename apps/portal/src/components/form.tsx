// Small form helpers the kit leaves to apps.
import { useId, type ReactNode } from "react";

/** A labelled group of controls (segmented choices, chip lists) with the kit's field look. */
export function FieldGroup({ label, hint, children }: { label: ReactNode; hint?: ReactNode; children: ReactNode }) {
  const id = useId();
  return (
    <div className="wb-field" role="group" aria-labelledby={`${id}-label`} aria-describedby={hint ? `${id}-hint` : undefined}>
      <span className="wb-field-label" id={`${id}-label`}>
        {label}
      </span>
      <div>{children}</div>
      {hint ? (
        <div className="wb-field-hint" id={`${id}-hint`}>
          {hint}
        </div>
      ) : null}
    </div>
  );
}

/** An inline form error (role=alert) or nothing. */
export function FormError({ error }: { error: string | null | undefined }) {
  return error ? (
    <div className="wb-form-error" role="alert">
      {error}
    </div>
  ) : null;
}
