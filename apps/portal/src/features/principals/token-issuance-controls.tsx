import type { PrincipalAgentTokenIssuance, PrincipalAgentTokenIssuanceSetting } from "../../types";
import { GROUP_TOKEN_ISSUANCE_OPTIONS, PRINCIPAL_TOKEN_ISSUANCE_OPTIONS, issuanceSettingBlocker } from "../../lib/token-issuance-policy";
import { Banner, Button, Checkbox, ErrorState, Select, SkeletonBlock } from "../../workbench";
import { usePolicyCatalog } from "../../data/queries";

/** The catalog query is gated by PolicyRead, independently of storage authority. */
export function useIssuanceRegistry() {
  const query = usePolicyCatalog();
  return { query, contexts: query.isSuccess && !query.isPlaceholderData && !query.isFetching ? query.data.executionContexts.allowedValues : undefined };
}

export function TokenIssuanceControls({ value, onChange, registry, group = false, disabled = false }: {
  value: PrincipalAgentTokenIssuanceSetting;
  onChange: (value: PrincipalAgentTokenIssuanceSetting) => void;
  registry: ReturnType<typeof useIssuanceRegistry>;
  group?: boolean;
  disabled?: boolean;
}) {
  const enabled = value.mode === "read_only" || value.mode === "write_capable";
  const choices = [...new Set([...(registry.query.data?.executionContexts.allowedValues ?? []), ...value.allowedExecutionContexts])];
  const blocker = issuanceSettingBlocker(value, registry.contexts);
  return <div className="wb-form-stack">
    <Select aria-label="Agent token issuance" value={value.mode} disabled={disabled} options={group ? GROUP_TOKEN_ISSUANCE_OPTIONS : PRINCIPAL_TOKEN_ISSUANCE_OPTIONS} onChange={(event) => {
      const mode = event.target.value as PrincipalAgentTokenIssuance;
      onChange({ mode, allowedExecutionContexts: mode === "disabled" || mode === "inherit" ? [] : value.allowedExecutionContexts });
    }} />
    {enabled ? <>
      {registry.query.isError ? <ErrorState compact title="Couldn’t load execution contexts" error={registry.query.error} onRetry={() => void registry.query.refetch()} /> : registry.query.isPending ? <SkeletonBlock lines={2} label="Loading execution contexts" /> : registry.query.isFetching ? <p className="wb-field-hint">Refreshing execution contexts.</p> : null}
      <fieldset className="pt-fieldset pt-fieldset--plain" disabled={disabled}>
        <legend>Permitted issuance contexts</legend>
        <div className="wb-form-stack" style={{ maxHeight: "18rem", overflowY: "auto" }}>{choices.map((context) => <Checkbox key={context} aria-label={context} label={<span className="wb-mono">{context}</span>} checked={value.allowedExecutionContexts.includes(context)} description={registry.contexts && !registry.contexts.includes(context) ? "No longer configured" : undefined} onChange={(event) => onChange({ ...value, allowedExecutionContexts: event.target.checked ? [...value.allowedExecutionContexts, context] : value.allowedExecutionContexts.filter((name) => name !== context) })} />)}</div>
      </fieldset>
      {blocker && registry.contexts ? <p className="wb-field-hint">{blocker}</p> : null}
    </> : null}
  </div>;
}

export function AccessDraftConflict({ conflict, kept, discard, keep }: { conflict: boolean; kept: boolean; discard: () => void; keep: () => void }) {
  return conflict ? <Banner tone="warning"><div className="wb-form-stack">
    <p>Saved settings changed since you started editing.</p>
    <div><Button onClick={discard}>Discard draft</Button> <Button onClick={keep}>Keep my draft</Button></div>
  </div></Banner> : kept ? <p className="wb-field-hint">Your next save replaces the edited values in the latest saved settings.</p> : null;
}
