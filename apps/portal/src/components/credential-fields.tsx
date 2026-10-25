// The Broker describes all fields for imported slots, personal and administered credentials.
// Values stay exact: HTTP Basic usernames and passwords may contain spaces and Unicode.
import { useState } from "react";
import type { CredentialInputDescriptor } from "../types";
import { MASKED_TEXT_SECURITY_SUPPORTED } from "../lib/helpers";
import { Field, IconButton, Input } from "../workbench";

export function CredentialFields({ descriptor, values, onChange, disabled = false }: {
  descriptor: CredentialInputDescriptor;
  values: Record<string, string>;
  onChange: (values: Record<string, string>) => void;
  disabled?: boolean;
}) {
  const [visible, setVisible] = useState<Record<string, boolean>>({});
  return <>
    {descriptor.inputPolicy === "http_basic" ? <p className="pt-prose wb-small">Enter the username and password or API token exactly, including spaces. Existing values cannot be revealed.</p> : descriptor.inputPolicy === "token_header" ? <p className="pt-prose wb-small">Paste the token value without a Bearer prefix. Existing values cannot be revealed.</p> : null}
    {descriptor.fields.map((field) => {
      const hidden = field.secret && !visible[field.name];
      return <Field key={field.name} label={field.prompt} hint={field.description} optional={!field.required}>
        <div className="flex gap-2">
          <Input
            type={hidden && !MASKED_TEXT_SECURITY_SUPPORTED ? "password" : "text"}
            className={hidden && MASKED_TEXT_SECURITY_SUPPORTED ? "pt-secret flex-1" : "flex-1"}
            value={values[field.name] ?? ""}
            onChange={(event) => onChange({ ...values, [field.name]: event.target.value })}
            required={field.required}
            disabled={disabled}
            autoComplete={field.secret ? "new-password" : "off"}
            autoCapitalize="none"
            spellCheck={false}
            data-lpignore="true"
            data-1p-ignore="true"
            data-bwignore="true"
          />
          {field.secret ? <IconButton variant="default" icon={visible[field.name] ? "eye-off" : "eye"} label={`${visible[field.name] ? "Hide" : "Show"} ${field.prompt}`} disabled={disabled} onClick={() => setVisible({ ...visible, [field.name]: !visible[field.name] })} /> : null}
        </div>
      </Field>;
    })}
  </>;
}
