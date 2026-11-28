// Who may hold each access key type: an account's Inherit from groups, Allow
// or Deny for each type, with the server's resolved result, and a group's
// list of the types it allows. Both are saved with the section they sit in.
// A type removed from the configuration while the draft still names it stays
// on screen, marked no longer configured, until the administrator removes it.
import { useRef } from "react";
import type { AccessKeyType, AccessKeyTypePolicy, GroupAccessKeyTypes, PrincipalAccessKeyTypes } from "../../types";
import { accessKeyTypeResult, accessKeyTypeSettingBlocker, principalAccessKeyTypeChoice, setGroupAccessKeyType, setPrincipalAccessKeyTypeChoice, unconfiguredAccessKeyTypes, type AccessKeyTypeChoice } from "../../lib/access-keys";
import { AppLink, Button, Checkbox, Select, StateCell } from "../../workbench";
import { paths } from "../../app/paths";

const CHOICES: { value: AccessKeyTypeChoice; label: string }[] = [
  { value: "inherit", label: "Inherit from groups" },
  { value: "allow", label: "Allow" },
  { value: "deny", label: "Deny" }
];

/** Every type the list has offered while the form is open, to name one that is no longer configured. */
function useSeenTypes(types: readonly AccessKeyType[]) {
  const seen = useRef(new Map<string, AccessKeyType>());
  for (const type of types) seen.current.set(type.id, type);
  return (id: string) => seen.current.get(id)?.displayName ?? id;
}

function TypeName({ type }: { type: AccessKeyType }) {
  return (
    <>
      <span className="pt-key-type-name">{type.displayName}</span>
      {type.description ? <span className="wb-small wb-muted pt-key-type-line">{type.description}</span> : null}
      <span className="wb-mono wb-small pt-key-type-line">{type.id}</span>
    </>
  );
}

/**
 * One row per configured type: the account's choice and, from the server,
 * what the saved setting gives. An edited row says the result follows saving.
 * A type the draft names that is no longer configured has its own row with a
 * Remove control; the section cannot be saved until it is removed.
 */
export function PrincipalAccessKeyTypeTable({ types, value, saved, policy, serviceAccount, writable, disabled, onChange }: {
  types: readonly AccessKeyType[];
  value: PrincipalAccessKeyTypes;
  saved: PrincipalAccessKeyTypes;
  policy: AccessKeyTypePolicy | null | undefined;
  serviceAccount: boolean;
  writable: boolean;
  disabled: boolean;
  onChange: (value: PrincipalAccessKeyTypes) => void;
}) {
  const nameOf = useSeenTypes(types);
  const gone = unconfiguredAccessKeyTypes(value, saved, types);
  const blocker = accessKeyTypeSettingBlocker(value, saved, types);
  return (
    <>
      <div className="wb-table-card overflow-x-auto">
        <table className="wb-table pt-key-type-table" aria-label="Access key types">
          <thead>
            <tr>
              <th scope="col">Access key type</th>
              <th scope="col">Setting</th>
              <th scope="col">Result</th>
            </tr>
          </thead>
          <tbody>
            {types.map((type) => {
              const choice = principalAccessKeyTypeChoice(value, type.id);
              const edited = choice !== principalAccessKeyTypeChoice(saved, type.id);
              const result = accessKeyTypeResult(policy, type.id, serviceAccount);
              return (
                <tr key={type.id}>
                  <th scope="row" className="pt-key-type-cell"><TypeName type={type} /></th>
                  <td>
                    {writable ? (
                      <Select aria-label={`${type.displayName} setting`} value={choice} disabled={disabled} options={CHOICES} onChange={(event) => onChange(setPrincipalAccessKeyTypeChoice(value, type.id, event.target.value as AccessKeyTypeChoice))} />
                    ) : (
                      CHOICES.find((item) => item.value === choice)!.label
                    )}
                  </td>
                  <td>
                    <span className="pt-key-type-result">
                      <StateCell label={result.label} tone={result.tone} />
                      <span className="wb-muted">
                        {" · "}{result.detail}
                        {result.groupIds.map((groupId, index) => <span key={groupId}>{index ? ", " : " "}<AppLink className="wb-link" href={paths.group(groupId)}>{groupId}</AppLink></span>)}
                      </span>
                    </span>
                    {edited ? <span className="wb-small wb-muted pt-key-type-line">Saved result; the change applies after saving.</span> : null}
                  </td>
                </tr>
              );
            })}
            {gone.map((id) => {
              const name = nameOf(id);
              return (
                <tr key={id}>
                  <th scope="row" className="pt-key-type-cell">
                    <span className="pt-key-type-name">{name}</span>
                    <span className="wb-mono wb-small pt-key-type-line">{id}</span>
                  </th>
                  <td>
                    <span className="wb-inline">
                      {CHOICES.find((item) => item.value === principalAccessKeyTypeChoice(value, id))!.label}
                      {writable ? <Button size="sm" aria-label={`Remove ${name} setting`} disabled={disabled} onClick={() => onChange(setPrincipalAccessKeyTypeChoice(value, id, "inherit"))}>Remove</Button> : null}
                    </span>
                  </td>
                  <td><StateCell label="No longer configured" tone="warning" /></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {blocker ? <p className="wb-field-hint">{blocker}</p> : null}
    </>
  );
}

/**
 * A group's types: checked when the group allows the type. A group cannot
 * deny. A type the draft allows that is no longer configured stays checked,
 * for unticking; the section cannot be saved until it is.
 */
export function GroupAccessKeyTypeChecks({ types, value, saved, disabled, onChange }: {
  types: readonly AccessKeyType[];
  value: GroupAccessKeyTypes;
  saved: GroupAccessKeyTypes;
  disabled: boolean;
  onChange: (value: GroupAccessKeyTypes) => void;
}) {
  const nameOf = useSeenTypes(types);
  const blocker = accessKeyTypeSettingBlocker(value, saved, types);
  return (
    <fieldset className="pt-fieldset pt-fieldset--plain" disabled={disabled}>
      <legend>Access key types this group allows</legend>
      <div className="wb-form-stack">
        {types.map((type) => (
          <Checkbox
            key={type.id}
            label={type.displayName}
            description={<>
              {type.description ? <span className="pt-key-type-line">{type.description}</span> : null}
              <span className="pt-key-type-line"><span className="wb-mono">{type.id}</span> · {type.selfService ? "people can issue it themselves" : "issued by administrators only"}</span>
            </>}
            checked={value.allow.includes(type.id)}
            onChange={(event) => onChange(setGroupAccessKeyType(value, type.id, event.target.checked))}
          />
        ))}
        {unconfiguredAccessKeyTypes(value, saved, types).map((id) => (
          <Checkbox
            key={id}
            label={nameOf(id)}
            description={<span className="pt-key-type-line"><span className="wb-mono">{id}</span> · no longer configured</span>}
            checked
            onChange={(event) => onChange(setGroupAccessKeyType(value, id, event.target.checked))}
          />
        ))}
      </div>
      {blocker ? <p className="wb-field-hint">{blocker}</p> : null}
    </fieldset>
  );
}
