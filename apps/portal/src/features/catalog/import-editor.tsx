import { AdminButton } from "../../components/admin-access";
// The import editor: creates an imported service draft or edits one, for HTTP
// MCP and OpenAPI adapters. Service ID and endpoint are fixed after creation;
// adapter settings and credential delivery are fixed once actions are accepted.
import { useState, type ReactNode } from "react";
import type { ImportDefinition, ImportOAuthRegistration, ImportPreviewResult } from "../../import-types";
import { importSourceKey } from "../../lib/imports";
import { importCredentialBindings, importOAuthError, matchingImportRegistrations, type ImportPersonalAuth } from "../../lib/import-credentials";
import { openApiBindings, openApiConnectionSettings, openApiDelivery, openApiSchemeLabel, openApiSecuritySchemes } from "../../lib/import-openapi";
import { errorMessage } from "../../lib/helpers";
import { Banner, Button, Checkbox, Field, Input, Select } from "../../workbench";
import { FormError } from "../../components/form";
import { adapterLabel } from "./catalog-data";
import { modalFrame, type EditorFrame } from "./catalog-ui";

export type ImportEditorProps = {
  /** The signed-in administrator (per-user discovery uses their credentials). */
  principal: string;
  /** The service being edited; absent when importing a new service. */
  data?: ImportPreviewResult | undefined;
  registrations: ImportOAuthRegistration[];
  availableKinds: string[];
  /** Imports are enabled by operator configuration (new imports only). */
  operatorEnabled?: boolean;
  onClose: () => void;
  onSave: (definition: ImportDefinition, confirmAffectedGrants: boolean) => Promise<unknown>;
  frame?: EditorFrame;
};

const SERVICE_ID = /^[a-z][a-z0-9_-]*$/;

function isUrl(value: string) {
  try {
    const url = new URL(value.trim());
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

/** Shared field checks: identity, endpoint, and the optional invocation limit. */
function commonIssues(draft: { creating: boolean; name: string; label: string; endpoint: string; requests: string; windowSeconds: string }, endpointLabel: string) {
  const issues: Record<string, string> = {};
  if (draft.creating) {
    if (!draft.name.trim()) issues.name = "Enter a service ID.";
    else if (draft.name.trim().length > 63 || !SERVICE_ID.test(draft.name.trim())) issues.name = "Use up to 63 lowercase letters, digits, hyphens or underscores, starting with a letter.";
    if (!isUrl(draft.endpoint)) issues.endpoint = `Enter the ${endpointLabel} as an http(s) URL.`;
  }
  if (!draft.label.trim()) issues.label = "Enter a display name.";
  if (draft.requests.trim()) {
    const requests = Number(draft.requests);
    const window = Number(draft.windowSeconds);
    if (!Number.isInteger(requests) || requests < 1 || requests > 1_000_000) issues.requests = "Use a whole number from 1 to 1,000,000.";
    if (!Number.isInteger(window) || window < 1 || window > 86_400) issues.windowSeconds = "Use a whole number of seconds from 1 to 86,400.";
  }
  return issues;
}

function invocationLimit(requests: string, windowSeconds: string) {
  return requests.trim() ? { invocationLimit: { requests: Number(requests), windowSeconds: Number(windowSeconds) } } : {};
}

/** Pending/error state and submit plumbing shared by both adapter forms. */
function useSave(onSave: ImportEditorProps["onSave"], onClose: () => void) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempted, setAttempted] = useState(false);
  async function submit(issues: Record<string, string>, definition: () => ImportDefinition, confirmed: boolean) {
    setAttempted(true);
    if (Object.keys(issues).length) return;
    setPending(true);
    setError(null);
    try {
      await onSave(definition(), confirmed);
      onClose();
    } catch (failure) {
      setError(errorMessage(failure));
      setPending(false);
    }
  }
  return { pending, error, attempted, submit };
}

function EditorFooter({ onClose, pending, disabled, editing }: { onClose: () => void; pending: boolean; disabled: boolean; editing: boolean }) {
  return (
    <>
      <Button onClick={onClose} disabled={pending}>
        Cancel
      </Button>
      <AdminButton type="submit" variant="primary" disabled={disabled} pending={pending}>
        {editing ? "Save configuration" : "Create draft"}
      </AdminButton>
    </>
  );
}

function LimitFields({
  requests,
  windowSeconds,
  onRequests,
  onWindow,
  disabled,
  issues
}: {
  requests: string;
  windowSeconds: string;
  onRequests: (value: string) => void;
  onWindow: (value: string) => void;
  disabled: boolean;
  issues: Record<string, string>;
}) {
  return (
    <div className="pt-catalog-row">
      <Field label="Invocation limit" optional hint="Requests per window for each principal; blank uses the broker default." error={issues.requests}>
        <Input type="number" inputMode="numeric" min={1} max={1000000} value={requests} disabled={disabled} onChange={(event) => onRequests(event.target.value)} />
      </Field>
      <Field label="Window in seconds" error={issues.windowSeconds}>
        <Input type="number" inputMode="numeric" min={1} max={86400} value={windowSeconds} disabled={disabled} onChange={(event) => onWindow(event.target.value)} />
      </Field>
    </div>
  );
}

function AffectedGrantsCheck({ count, checked, onChange, disabled }: { count: number; checked: boolean; onChange: (checked: boolean) => void; disabled: boolean }) {
  if (!count) return null;
  return (
    <Banner tone="warning" slim title="Existing grants">
      <Checkbox
        label={`I reviewed the ${count} existing grant(s) that this configuration may affect.`}
        checked={checked}
        disabled={disabled}
        onChange={(event) => {
          event.stopPropagation();
          onChange(event.target.checked);
        }}
      />
    </Banner>
  );
}

/** Import type picker plus the form for the chosen adapter kind. */
export function ImportEditor(props: ImportEditorProps) {
  const { data, availableKinds } = props;
  const old = data?.service.definition;
  // Until the administrator picks one, follow the operator's kinds (they may still be loading).
  const [chosen, setKind] = useState<string | null>(null);
  const kind = chosen ?? old?.adapterKind ?? (availableKinds.includes("mcp_http") ? "mcp_http" : availableKinds[0] ?? "");
  const kindPicker = (disabled: boolean) => (
    <Field label="Import type" hint={old ? "The import type is fixed after creation." : undefined}>
      <Select value={kind} disabled={disabled || Boolean(old)} onChange={(event) => setKind(event.target.value)}>
        {!kind ? <option value="">No import types enabled</option> : null}
        {old && !availableKinds.includes(kind) ? <option value={kind}>{kind} (unavailable)</option> : null}
        {availableKinds.map((value) => (
          <option key={value} value={value}>
            {adapterLabel(value)}
          </option>
        ))}
      </Select>
    </Field>
  );
  return kind === "openapi_http" ? <OpenApiImportForm {...props} kindPicker={kindPicker} /> : <McpImportForm {...props} kind={kind} kindPicker={kindPicker} />;
}

function McpImportForm({
  principal,
  data,
  registrations,
  operatorEnabled = true,
  onClose,
  onSave,
  frame = modalFrame,
  kind,
  kindPicker
}: ImportEditorProps & { kind: string; kindPicker: (disabled: boolean) => ReactNode }) {
  const old = data?.service.definition;
  const mutable = !data || (data.service.status === "draft" && data.service.actions.length === 0);
  const personalBinding = old?.executionBindings.find((binding) => binding.ownerMode === "per_user");
  const [name, setName] = useState(old?.service ?? "");
  const [label, setLabel] = useState(old?.displayName ?? "");
  const [endpoint, setEndpoint] = useState(old?.endpoint ?? "");
  const [shared, setShared] = useState(!old || old.executionBindings.some((binding) => binding.ownerMode === "service"));
  const [personal, setPersonal] = useState(Boolean(personalBinding));
  const [personalAuth, setPersonalAuth] = useState<ImportPersonalAuth>(
    personalBinding?.status === "unsupported" || (personalBinding?.mechanism === "oauth" && personalBinding.adapterId !== "mcp_oauth")
      ? "retained"
      : personalBinding?.mechanism ?? "static_token"
  );
  const [registrationId, setRegistrationId] = useState(personalBinding?.registrationId ?? "");
  const [profile, setProfile] = useState(personalBinding?.profile ?? "");
  const delivery = old?.executionBindings[0]?.delivery;
  const [header, setHeader] = useState(delivery?.kind === "raw_header" ? delivery.name : "");
  const [raw, setRaw] = useState(delivery?.kind === "raw_header");
  const [discovery, setDiscovery] = useState(old?.discovery.kind ?? "execution");
  const [discoveryPrincipal, setDiscoveryPrincipal] = useState(old?.discovery.kind === "per_user" ? old.discovery.principal : principal);
  const [transport, setTransport] = useState(old?.transportAuth ?? false);
  const [requests, setRequests] = useState(String(old?.invocationLimit?.requests ?? ""));
  const [windowSeconds, setWindowSeconds] = useState(String(old?.invocationLimit?.windowSeconds ?? 60));
  const [confirmed, setConfirmed] = useState(false);
  const save = useSave(onSave, onClose);
  const busy = save.pending;

  const oauth = personal && personalAuth === "oauth";
  const approved = matchingImportRegistrations(registrations, endpoint);
  const registration = approved.find((entry) => entry.id === registrationId);
  const permissionProfile = registration?.permissionProfiles.find((entry) => entry.id === profile);
  const bindings = importCredentialBindings(old?.executionBindings ?? [], {
    shared,
    personal,
    personalAuth,
    registrationId,
    profile,
    delivery: raw ? { kind: "raw_header", name: header.trim() } : { kind: "bearer" }
  });
  const supportedPersonal = bindings.some((binding) => binding.ownerMode === "per_user" && binding.status === "configured");
  const authError = oauth ? importOAuthError(registrations, endpoint, registrationId, profile, raw, transport) : null;
  const bindingChanged = Boolean(old && importSourceKey(old.executionBindings) !== importSourceKey(bindings));
  const affected = bindingChanged ? data?.affectedGrants ?? [] : [];
  const retainedMissingRegistration = Boolean(oauth && authError && !bindingChanged && personalBinding);

  const issues = commonIssues({ creating: !old, name, label, endpoint, requests, windowSeconds }, "HTTP MCP endpoint");
  if (raw && !header.trim()) issues.header = "Enter the header that carries the execution token.";
  if (discovery === "per_user" && !discoveryPrincipal.trim()) issues.principal = "Sign in again to use your personal credentials.";
  const shown = save.attempted ? issues : {};
  const blocked =
    !kind ||
    (!old && !operatorEnabled) ||
    (!shared && !personal) ||
    (Boolean(authError) && !retainedMissingRegistration) ||
    (discovery === "execution" && !shared) ||
    (discovery === "per_user" && !supportedPersonal) ||
    (affected.length > 0 && !confirmed);

  function definition(): ImportDefinition {
    return {
      service: name.trim(),
      displayName: label.trim(),
      endpoint: endpoint.trim(),
      adapterKind: kind,
      connectionSettings: old?.connectionSettings ?? {},
      executionBindings: bindings,
      discovery: discovery === "per_user" ? { kind: "per_user", principal: discoveryPrincipal.trim() } : { kind: discovery },
      transportAuth: transport,
      ...invocationLimit(requests, windowSeconds)
    };
  }

  const body = (
    <div className="pt-form pt-catalog-form" onChange={() => setConfirmed(false)}>
      {!old && !operatorEnabled ? (
        <Banner tone="warning" slim>
          Imports are disabled by operator configuration.
        </Banner>
      ) : null}
      {kindPicker(busy)}
      <div className="pt-catalog-row">
        <Field label="Service ID" hint={old ? "Fixed after creation." : "Lowercase; used in grants and agent calls."} error={shown.name}>
          <Input mono required maxLength={63} value={name} disabled={Boolean(old) || busy} onChange={(event) => setName(event.target.value)} autoComplete="off" spellCheck={false} />
        </Field>
        <Field label="Display name" error={shown.label}>
          <Input required maxLength={256} value={label} disabled={busy} onChange={(event) => setLabel(event.target.value)} />
        </Field>
      </div>
      <Field
        label="HTTP MCP endpoint"
        hint="The endpoint must be allowed by operator configuration. Service ID and endpoint are fixed after creation; credential delivery is fixed after accepting actions."
        error={shown.endpoint}
      >
        <Input mono required type="url" placeholder="https://mcp.example.test/mcp" value={endpoint} disabled={Boolean(old) || busy} onChange={(event) => setEndpoint(event.target.value)} spellCheck={false} />
      </Field>
      {old && mutable ? (
        <Banner tone="warning" slim>
          Changing token delivery removes stored execution and discovery tokens. Set them again after saving. Existing personal credentials must be removed first.
        </Banner>
      ) : null}
      <fieldset className="pt-fieldset">
        <legend>Execution credentials</legend>
        <Checkbox
          label="Shared service token"
          checked={shared}
          disabled={busy || old?.executionBindings.some((binding) => binding.ownerMode === "service")}
          onChange={(event) => setShared(event.target.checked)}
        />
        <Checkbox label="Personal credentials for each user" checked={personal} disabled={busy || Boolean(personalBinding)} onChange={(event) => setPersonal(event.target.checked)} />
        {personal ? (
          <>
            <Field label="Personal authentication">
              <Select
                value={personalAuth}
                disabled={busy}
                onChange={(event) => {
                  const value = event.target.value as ImportPersonalAuth;
                  setPersonalAuth(value);
                  if (value === "oauth" && mutable) {
                    setRaw(false);
                    setTransport(false);
                  }
                }}
              >
                <option value="static_token">Static token</option>
                <option value="oauth" disabled={!mutable && raw}>
                  OAuth connection
                </option>
                {personalBinding?.status === "unsupported" || (personalBinding?.adapterId && personalBinding.adapterId !== "mcp_oauth") ? (
                  <option value="retained">Retain unsupported binding</option>
                ) : null}
              </Select>
            </Field>
            {!mutable && raw ? <p className="pt-prose wb-small">OAuth requires Bearer delivery. Create a new service identity to change this header destination.</p> : null}
            {oauth ? (
              <>
                <div className="pt-catalog-row">
                  <Field label="OAuth registration">
                    <Select
                      value={registrationId}
                      disabled={busy}
                      onChange={(event) => {
                        setRegistrationId(event.target.value);
                        setProfile("");
                      }}
                    >
                      <option value="">Select an approved registration</option>
                      {registrationId && !registration ? <option value={registrationId}>{registrationId} (unavailable)</option> : null}
                      {approved.map((entry) => (
                        <option key={entry.id} value={entry.id}>
                          {entry.id}
                        </option>
                      ))}
                    </Select>
                  </Field>
                  <Field label="Permission profile">
                    <Select value={profile} disabled={busy || !registration} onChange={(event) => setProfile(event.target.value)}>
                      <option value="">Select approved permissions</option>
                      {profile && !permissionProfile ? <option value={profile}>{profile} (unavailable)</option> : null}
                      {registration?.permissionProfiles.map((entry) => (
                        <option key={entry.id} value={entry.id}>
                          {entry.id}
                        </option>
                      ))}
                    </Select>
                  </Field>
                </div>
                {registration ? (
                  <p className="pt-prose wb-small pt-catalog-break">
                    Authorization server: <span className="wb-mono">{registration.issuer}</span>
                    <br />
                    Resource: <span className="wb-mono">{registration.resource}</span>
                  </p>
                ) : null}
                {permissionProfile ? <p className="pt-prose wb-small">{permissionProfile.scopeMode === "server_default" ? "Server-default permissions" : `Requested scopes: ${permissionProfile.scopes.join(", ")}`}</p> : null}
                {authError ? (
                  <Banner tone="warning" slim>
                    {authError}
                    {retainedMissingRegistration ? " The existing binding is retained and remains unavailable." : ""}
                  </Banner>
                ) : null}
              </>
            ) : null}
          </>
        ) : null}
        <p className="pt-prose wb-small">
          Grants select one supported mode. Personal credentials never fall back to a shared token. Each user connects their own OAuth account from Credentials.
        </p>
        <div className="pt-catalog-row">
          <Field label="Credential delivery">
            <Select
              disabled={!mutable || busy || oauth}
              value={raw ? "raw" : "bearer"}
              onChange={(event) => {
                setRaw(event.target.value === "raw");
                if (event.target.value !== "raw") setTransport(false);
              }}
            >
              <option value="bearer">Authorization: Bearer</option>
              <option value="raw">Dedicated header</option>
            </Select>
          </Field>
          {raw ? (
            <Field label="Execution token header" error={shown.header}>
              <Input mono required value={header} disabled={!mutable || busy} onChange={(event) => setHeader(event.target.value)} spellCheck={false} />
            </Field>
          ) : null}
        </div>
        {raw ? <Checkbox label="Separate transport bearer token" checked={transport} disabled={busy || oauth} onChange={(event) => setTransport(event.target.checked)} /> : null}
      </fieldset>
      <Field label="Discovery credential">
        <Select
          value={discovery}
          disabled={busy}
          onChange={(event) => {
            setDiscovery(event.target.value as typeof discovery);
            if (event.target.value === "per_user") setDiscoveryPrincipal(principal);
          }}
        >
          <option value="execution" disabled={!shared}>
            Shared execution token
          </option>
          <option value="slot">Separate discovery token</option>
          <option value="per_user" disabled={!supportedPersonal}>
            An administrator's personal credentials
          </option>
        </Select>
      </Field>
      {discovery === "per_user" ? (
        <Field
          label="Discovery principal ID"
          hint={`Save the draft, then ${oauth ? "connect your OAuth account" : "set your personal token"} to discover tools before granting access.`}
          error={shown.principal}
        >
          <Input mono required readOnly value={discoveryPrincipal} disabled={busy} />
        </Field>
      ) : null}
      <LimitFields requests={requests} windowSeconds={windowSeconds} onRequests={setRequests} onWindow={setWindowSeconds} disabled={busy} issues={shown} />
      <AffectedGrantsCheck count={affected.length} checked={confirmed} onChange={setConfirmed} disabled={busy} />
      <FormError error={save.error} />
    </div>
  );

  return frame({
    title: data ? "Edit imported service" : "Import service",
    body,
    footer: <EditorFooter onClose={onClose} pending={busy} disabled={blocked} editing={Boolean(data)} />,
    onSubmit: () => void save.submit(issues, definition, confirmed),
    onClose,
    pending: busy
  });
}

function OpenApiImportForm({
  data,
  operatorEnabled = true,
  onClose,
  onSave,
  frame = modalFrame,
  kindPicker
}: ImportEditorProps & { kindPicker: (disabled: boolean) => ReactNode }) {
  const old = data?.service.definition;
  const mutable = !data || (data.service.status === "draft" && data.service.actions.length === 0);
  const [name, setName] = useState(old?.service ?? "");
  const [label, setLabel] = useState(old?.displayName ?? "");
  const [endpoint, setEndpoint] = useState(old?.endpoint ?? "");
  const [definitionUrl, setDefinitionUrl] = useState(old?.connectionSettings.definitionUrl ?? "");
  const [documentAuth, setDocumentAuth] = useState(old?.connectionSettings.definitionAuthKind ?? "none");
  const [documentHeader, setDocumentHeader] = useState(old?.connectionSettings.definitionAuthHeader ?? "");
  const [securityScheme, setSecurityScheme] = useState(old?.connectionSettings.securityScheme ?? "");
  const [shared, setShared] = useState(!old || old.executionBindings.some((binding) => binding.ownerMode === "service"));
  const [personal, setPersonal] = useState(Boolean(old?.executionBindings.some((binding) => binding.ownerMode === "per_user")));
  const [requests, setRequests] = useState(String(old?.invocationLimit?.requests ?? ""));
  const [windowSeconds, setWindowSeconds] = useState(String(old?.invocationLimit?.windowSeconds ?? 60));
  const [confirmed, setConfirmed] = useState(false);
  const save = useSave(onSave, onClose);
  const busy = save.pending;

  const schemes = openApiSecuritySchemes(data?.preview?.manifest);
  const selectedScheme = schemes.find((scheme) => scheme.name === securityScheme);
  const delivery = mutable && selectedScheme ? openApiDelivery(selectedScheme) : old?.executionBindings[0]?.delivery ?? { kind: "bearer" as const };
  const bindings = openApiBindings(old?.executionBindings ?? [], shared, personal, delivery);
  const affected = old && importSourceKey(old.executionBindings) !== importSourceKey(bindings) ? data?.affectedGrants ?? [] : [];
  const unknownNewScheme = Boolean(securityScheme && !selectedScheme && securityScheme !== old?.connectionSettings.securityScheme);

  const issues = commonIssues({ creating: !old, name, label, endpoint, requests, windowSeconds }, "API base URL");
  if (mutable && !isUrl(definitionUrl)) issues.definitionUrl = "Enter the OpenAPI definition URL as an http(s) URL.";
  if (mutable && documentAuth === "raw_header" && !documentHeader.trim()) issues.documentHeader = "Enter the header that carries the discovery token.";
  const shown = save.attempted ? issues : {};
  const blocked = (!old && !operatorEnabled) || (!shared && !personal) || unknownNewScheme || (affected.length > 0 && !confirmed);

  function definition(): ImportDefinition {
    return {
      service: name.trim(),
      displayName: label.trim(),
      adapterKind: "openapi_http",
      endpoint: endpoint.trim(),
      connectionSettings: openApiConnectionSettings(old?.connectionSettings, mutable, {
        definitionUrl,
        definitionAuthKind: documentAuth,
        definitionAuthHeader: documentHeader,
        securityScheme
      }),
      executionBindings: bindings,
      discovery: { kind: documentAuth === "none" ? "anonymous" : "slot" },
      transportAuth: false,
      ...invocationLimit(requests, windowSeconds)
    };
  }

  const body = (
    <div className="pt-form pt-catalog-form" onChange={() => setConfirmed(false)}>
      {!old && !operatorEnabled ? (
        <Banner tone="warning" slim>
          Imports are disabled by operator configuration.
        </Banner>
      ) : null}
      {kindPicker(busy)}
      <div className="pt-catalog-row">
        <Field label="Service ID" hint={old ? "Fixed after creation." : "Lowercase; used in grants and agent calls."} error={shown.name}>
          <Input mono required maxLength={63} value={name} disabled={Boolean(old) || busy} onChange={(event) => setName(event.target.value)} autoComplete="off" spellCheck={false} />
        </Field>
        <Field label="Display name" error={shown.label}>
          <Input required maxLength={256} value={label} disabled={busy} onChange={(event) => setLabel(event.target.value)} />
        </Field>
      </div>
      <Field label="API base URL" error={shown.endpoint}>
        <Input mono required type="url" placeholder="https://api.example.test/v1" value={endpoint} disabled={Boolean(old) || busy} onChange={(event) => setEndpoint(event.target.value)} spellCheck={false} />
      </Field>
      <Field
        label="OpenAPI definition URL"
        hint="Both URLs must be allowed by the operator. The definition describes operations; calls use the API base URL. OpenAPI 3.1 JSON is supported."
        error={shown.definitionUrl}
      >
        <Input
          mono
          required
          type="url"
          placeholder="https://docs.example.test/openapi.json"
          value={definitionUrl}
          disabled={!mutable || busy}
          onChange={(event) => setDefinitionUrl(event.target.value)}
          spellCheck={false}
        />
      </Field>
      {old && mutable ? (
        <Banner tone="warning" slim>
          Changing definition settings or API token delivery removes stored execution and discovery tokens. Set them again after saving. Existing personal credentials must be
          removed first.
        </Banner>
      ) : null}
      <fieldset className="pt-fieldset">
        <legend>Definition document access</legend>
        <div className="pt-catalog-row">
          <Field label="Definition authentication">
            <Select value={documentAuth} disabled={busy || !mutable} onChange={(event) => setDocumentAuth(event.target.value)}>
              <option value="none">Public document (no credentials)</option>
              <option value="bearer">Separate discovery Bearer token</option>
              <option value="raw_header">Separate discovery header token</option>
            </Select>
          </Field>
          {documentAuth === "raw_header" ? (
            <Field label="Definition token header" error={shown.documentHeader}>
              <Input mono required value={documentHeader} disabled={busy || !mutable} onChange={(event) => setDocumentHeader(event.target.value)} spellCheck={false} />
            </Field>
          ) : null}
        </div>
        <p className="pt-prose wb-small">
          {documentAuth === "none"
            ? "Loading this document sends no credentials."
            : "Save the draft, then set its discovery token. This token only reads the definition document."}
        </p>
      </fieldset>
      <fieldset className="pt-fieldset">
        <legend>API execution credentials</legend>
        <Checkbox
          label="Shared service token"
          checked={shared}
          disabled={busy || old?.executionBindings.some((binding) => binding.ownerMode === "service")}
          onChange={(event) => setShared(event.target.checked)}
        />
        <Checkbox
          label="Personal credentials for each user"
          checked={personal}
          disabled={busy || old?.executionBindings.some((binding) => binding.ownerMode === "per_user")}
          onChange={(event) => setPersonal(event.target.checked)}
        />
        <p className="pt-prose wb-small">
          API calls use static tokens. Grants select shared or personal credentials. Personal credentials never fall back to a shared token. Existing credential modes are retained.
        </p>
        <Field label="API security scheme">
          <Select value={securityScheme} disabled={busy || !mutable || !schemes.length} onChange={(event) => setSecurityScheme(event.target.value)}>
            <option value="">{schemes.length ? "Select a scheme from the definition" : "Load the definition to discover schemes"}</option>
            {securityScheme && !selectedScheme ? <option value={securityScheme}>{securityScheme} (retained)</option> : null}
            {schemes.map((scheme) => (
              <option key={scheme.name} value={scheme.name}>
                {openApiSchemeLabel(scheme)}
              </option>
            ))}
          </Select>
        </Field>
        {securityScheme ? (
          <p className="pt-prose wb-small">
            Token delivery: {delivery.kind === "bearer" ? "Authorization: Bearer" : delivery.name}.{mutable ? " Save changes, then refresh the definition to review operations." : ""}
          </p>
        ) : (
          <p className="pt-prose wb-small">Create the draft and load its definition first. Operations remain unavailable until you select an API security scheme and refresh.</p>
        )}
        {!mutable && selectedScheme && importSourceKey(delivery) !== importSourceKey(openApiDelivery(selectedScheme)) ? (
          <Banner tone="warning" slim>
            The discovered scheme now uses different token delivery. Create a new service to use that destination.
          </Banner>
        ) : null}
        {!mutable ? <p className="pt-prose wb-small">The definition settings and token delivery are fixed after accepting actions. Create a new service to change them.</p> : null}
      </fieldset>
      <LimitFields requests={requests} windowSeconds={windowSeconds} onRequests={setRequests} onWindow={setWindowSeconds} disabled={busy} issues={shown} />
      <AffectedGrantsCheck count={affected.length} checked={confirmed} onChange={setConfirmed} disabled={busy} />
      <FormError error={save.error} />
    </div>
  );

  return frame({
    title: data ? "Edit imported service" : "Import service",
    body,
    footer: <EditorFooter onClose={onClose} pending={busy} disabled={blocked} editing={Boolean(data)} />,
    onSubmit: () => void save.submit(issues, definition, confirmed),
    onClose,
    pending: busy
  });
}
