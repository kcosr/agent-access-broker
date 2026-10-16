// Credential connections of the signed-in user (My access › Credentials) or an
// administered principal (the user page's Credentials tab): one row per
// connection with a stored token form, one per OAuth registration (self), and
// one per retained stored credential the configuration no longer selects. A
// drawer stores, replaces, verifies, deletes, connects or disconnects.
import { canWriteSubject } from "../../lib/capabilities";
import { useSession } from "../../app/session";
import { useEffect, useMemo, useState } from "react";
import type { CredentialConnection, CredentialMetadata, CredentialTarget, OAuthConnectionTarget } from "../../types";
import { MASKED_TEXT_SECURITY_SUPPORTED, credentialStatus, credentialTone, errorMessage } from "../../lib/helpers";
import { consumerSummary, oauthRowKey, repositoryConsumers, retainedRowKey } from "../../lib/credentials";
import { urlParam } from "../../lib/url-state";
import {
  Badge,
  Button,
  type DataColumn,
  DataTable,
  Drawer,
  DrawerSection,
  EmptyState,
  ErrorState,
  Field,
  FilterInput,
  Icon,
  IconButton,
  Input,
  KeyValue,
  ListFooter,
  Seg,
  Select,
  StateCell,
  StatePill,
  Time,
  type Tone,
  Toolbar,
  ToolbarRow,
  ToolbarSummary
} from "../../workbench";
import { sortRows } from "../../lib/table-sort";
import type { AccountSubject } from "../../app/active-route";
import { useActionRunner } from "../../app/actions";
import { useTableUrlState } from "../../app/list-state";
import { useModal } from "../../app/modal";
import { useConsoleData, useOAuthConnections } from "../../data/queries";
import { useCredentialActions } from "../../mutations/credentials";
import { FormError } from "../../components/form";
import {
  AUTHORIZATION_TAB_NOTICE,
  OAuthConnectionButtons,
  OAuthConnectionDetails,
  oauthAccountLabel,
  oauthConnected,
  oauthConnectionStatus,
  oauthConnectUnavailableMessage,
  oauthScopeEvidence,
  useOAuthConnectionActions
} from "../../components/oauth-connections";

const FILTERS = ["all", "attention", "missing", "unused"] as const;

export const CREDENTIAL_STATE = {
  status: urlParam.oneOf(FILTERS, "all"),
  sort: urlParam.sort(["service", "verified"]),
  q: urlParam.text(),
  credential: urlParam.text()
};

/**
 * One list row: a connection storing a token (`key` is the connection ID), a
 * connection offering this principal no method, an OAuth registration
 * (`oauth:<registration>`), or a retained stored row (`retained:<credentialId>`).
 */
export type CredentialRow =
  | { kind: "token"; key: string; connection: CredentialConnection; target: CredentialTarget | undefined }
  | { kind: "unavailable"; key: string; connection: CredentialConnection }
  | { kind: "oauth"; key: string; oauth: OAuthConnectionTarget }
  | { kind: "retained"; key: string; credential: CredentialMetadata };


function rowName(row: CredentialRow) {
  switch (row.kind) {
    case "token":
    case "unavailable":
      return row.connection.displayName;
    case "oauth":
      return row.oauth.displayName;
    case "retained":
      return `${row.credential.service}/${row.credential.name}`;
  }
}

function rowConsumers(row: CredentialRow) {
  switch (row.kind) {
    case "token":
    case "unavailable":
      return consumerSummary(row.connection.consumers, row.connection.otherConsumers);
    case "oauth":
      return consumerSummary(row.oauth.consumers, row.oauth.otherConsumers);
    case "retained":
      return "";
  }
}

function rowState(row: CredentialRow): { label: string; tone: Tone; quiet: boolean } {
  switch (row.kind) {
    case "token": {
      const label = credentialStatus(row.connection.credential);
      return { label, tone: row.connection.credential ? credentialTone(row.connection.credential) : "neutral", quiet: label === "Upstream verified" || label === "Local verified" };
    }
    case "unavailable":
      return { label: "Unavailable", tone: "neutral", quiet: false };
    case "oauth": {
      const status = oauthConnectionStatus(row.oauth);
      return { label: status.label, tone: status.tone, quiet: row.oauth.connection?.status === "ready" };
    }
    case "retained":
      return { label: "Not used", tone: "neutral", quiet: false };
  }
}

function needsAttention(row: CredentialRow) {
  if (row.kind === "token") {
    const status = credentialStatus(row.connection.credential);
    return Boolean(row.connection.credential) && (status === "Not verified" || status === "Verification failed");
  }
  if (row.kind === "oauth") return row.oauth.connection?.status === "reconnect_required" || row.oauth.connection?.status === "operator_action_required";
  return false;
}

function isMissing(row: CredentialRow) {
  if (row.kind === "token") return !row.connection.credential;
  if (row.kind === "oauth") return !oauthConnected(row.oauth);
  return false;
}

export function useCredentialList(subject: AccountSubject) {
  const data = useConsoleData(subject);
  const oauth = useOAuthConnections(!subject.administered);
  const connections = useOAuthConnectionActions("/ui/credentials");
  const rows = useMemo<CredentialRow[]>(() => {
    const targets = new Map(data.targets.map((target) => [target.connection, target]));
    return [
      ...data.credentials.connections.flatMap<CredentialRow>((connection) => {
        if (connection.method === "token") return [{ kind: "token", key: connection.connection, connection, target: targets.get(connection.connection) }];
        if (connection.method === "unavailable") return [{ kind: "unavailable", key: connection.connection, connection }];
        // OAuth connections appear once per registration, from the OAuth rows.
        return [];
      }),
      ...(subject.administered ? [] : (oauth.data ?? []).map<CredentialRow>((target) => ({ kind: "oauth", key: oauthRowKey(target.registration), oauth: target }))),
      ...data.credentials.retained.map<CredentialRow>((credential) => ({ kind: "retained", key: retainedRowKey(credential.credentialId), credential }))
    ];
  }, [data.targets, data.credentials, oauth.data, subject.administered]);
  const filter = (state: { status: (typeof FILTERS)[number]; q: string }) => {
    const query = state.q.trim().toLowerCase();
    return rows.filter((row) => {
      if (state.status === "attention" && !needsAttention(row)) return false;
      if (state.status === "missing" && !isMissing(row)) return false;
      if (state.status === "unused" && row.kind !== "retained") return false;
      const profile = row.kind === "token" ? row.connection.profile : row.kind === "retained" ? row.credential.profile : "";
      return !query || `${row.key} ${rowName(row)} ${rowConsumers(row)} ${profile ?? ""}`.toLowerCase().includes(query);
    });
  };
  const list = useTableUrlState(CREDENTIAL_STATE, "credential");
  const shown = sortRows(
    filter(list.state),
    list.state.sort,
    (row, key) => (key === "verified" ? (row.kind === "token" ? row.connection.credential?.lastVerifiedAt : undefined) : rowName(row)),
    (a, b) => Number(a.kind === "retained") - Number(b.kind === "retained") || rowName(a).localeCompare(rowName(b)) || a.key.localeCompare(b.key)
  );
  const counts = {
    all: rows.length,
    settable: rows.filter((row) => row.kind === "token" || row.kind === "oauth").length,
    attention: rows.filter(needsAttention).length,
    missing: rows.filter(isMissing).length,
    unused: rows.filter((row) => row.kind === "retained").length
  };
  const open = list.openId ? rows.find((row) => row.key === list.openId) ?? null : null;
  return { subject, data, oauth, connections, rows, list, shown, counts, open };
}

export type CredentialListModel = ReturnType<typeof useCredentialList>;

export function CredentialToolbar({ model }: { model: CredentialListModel }) {
  const { list, counts } = model;
  return (
    <Toolbar>
      <ToolbarRow>
        <Seg
          label="Credential status"
          value={list.state.status}
          onChange={(status) => list.setState({ status, credential: "" })}
          options={[
            { value: "all", label: "All", count: counts.all },
            { value: "attention", label: "Needs attention", icon: "alert", tone: "warning", count: counts.attention },
            { value: "missing", label: "Not set up", count: counts.missing },
            ...(counts.unused ? [{ value: "unused" as const, label: "Not used", count: counts.unused }] : [])
          ]}
        />
        <FilterInput value={list.state.q} onChange={(q) => list.setState({ q })} placeholder="Filter credentials…" debounceMs={150} />
        <ToolbarSummary grow>
          <b>{counts.settable - counts.missing}</b> of {counts.settable} set up
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );
}

export function CredentialRows({ model }: { model: CredentialListModel }) {
  const { data, oauth, connections, rows, list, shown, subject } = model;
  const actions = useCredentialActions(subject);
  const writable = canWriteSubject(useSession().session, subject);
  const { confirm } = useModal();
  const filtered = Boolean(list.state.q || list.state.status !== "all");
  // Server-default evidence and unavailability notes need room to wrap.
  const wrapPermissions = rows.some((row) => row.kind === "oauth" && (row.oauth.scopeMode === "server_default" || row.oauth.connectUnavailableReason !== null));
  const columns = useMemo<DataColumn<CredentialRow>[]>(
    () => [
      {
        key: "status",
        header: "Status",
        cell: (row) => {
          const state = rowState(row);
          return <StateCell label={state.label} tone={state.tone} quiet={state.quiet} />;
        }
      },
      {
        key: "service",
        header: "Connection",
        primary: true,
        sortable: true,
        truncate: true,
        minWidth: "14ch",
        cell: (row) => <span className={row.kind === "retained" ? "wb-mono" : undefined}>{rowName(row)}</span>
      },
      {
        key: "consumers",
        header: "Used by",
        priority: 2,
        truncate: true,
        minWidth: "14ch",
        cell: (row) => {
          if (row.kind === "retained") return <span className="wb-muted">Not used</span>;
          // Without an entitled service, the drawer counts the others.
          const entitled = row.kind === "oauth" ? row.oauth.consumers : row.connection.consumers;
          return entitled.length ? rowConsumers(row) : <span className="wb-muted">No current grants</span>;
        }
      },
      {
        key: "method",
        header: "Method",
        priority: 4,
        truncate: true,
        minWidth: "10ch",
        className: "wb-cell-muted",
        cell: (row) => {
          if (row.kind === "token") return row.connection.profile;
          if (row.kind === "retained") return row.credential.profile;
          if (row.kind === "oauth") {
            return (
              <span>
                OAuth · <span>{oauthAccountLabel(row.oauth)}</span>
              </span>
            );
          }
          return "None for this account";
        }
      },
      {
        key: "permissions",
        header: "Permissions",
        priority: 4,
        truncate: !wrapPermissions,
        wrap: wrapPermissions,
        minWidth: wrapPermissions ? "26ch" : "12ch",
        className: "wb-cell-muted",
        hideWhenEmpty: true,
        cell: (row) => {
          if (row.kind !== "oauth") return null;
          const target = row.oauth;
          const evidence = target.scopeMode === "server_default" ? oauthScopeEvidence(target) : null;
          const unavailable = oauthConnectUnavailableMessage(target);
          return (
            <span>
              <span>{target.scopeMode === "explicit" ? target.connectionDescription ?? "Shown during connection" : "Server-default permissions"}</span>
              {evidence ? (
                <>
                  <br />
                  <span className="wb-small">{evidence}</span>
                </>
              ) : null}
              {unavailable ? (
                <>
                  <br />
                  <span className="wb-small">{unavailable}</span>
                </>
              ) : null}
            </span>
          );
        }
      },
      {
        key: "error",
        header: "Last error",
        priority: 3,
        className: "wb-cell-mono",
        // Only a token whose verification failed has one.
        hideWhenEmpty: true,
        cell: (row) => {
          const credential = row.kind === "token" ? row.connection.credential : null;
          return credential && credentialStatus(credential) === "Verification failed" ? credential.lastVerificationErrorCode ?? "" : "";
        }
      },
      {
        key: "verified",
        header: "Verified",
        sortable: true,
        firstSortDir: "desc",
        priority: 2,
        cell: (row) => {
          if (row.kind !== "token") return null;
          const credential = row.connection.credential;
          return credential?.lastVerifiedAt ? <Time value={credential.lastVerifiedAt} /> : <span className="wb-muted">{credential ? "Never" : ""}</span>;
        }
      },
      {
        key: "row-actions",
        header: <span className="wb-sr-only">Row actions</span>,
        className: "wb-cell-actions",
        hideWhenEmpty: true,
        cell: (row) => {
          if (row.kind === "oauth") return <OAuthConnectionButtons target={row.oauth} connections={connections} />;
          if (row.kind === "retained" && writable) {
            return (
              <Button size="sm" variant="danger-ghost" icon="trash" onClick={() => confirmRetainedDelete(confirm, row.credential, () => actions.removeRetained(row.credential))}>
                Delete
              </Button>
            );
          }
          return null;
        }
      }
    ],
    [connections, actions, writable, confirm, wrapPermissions]
  );
  return (
    <>
      {connections.pending ? (
        <p className="wb-small wb-muted">
          Finish or close the open authorization tab before connecting another account. {AUTHORIZATION_TAB_NOTICE}
        </p>
      ) : null}
      <DataTable
        label="Credentials"
        rows={shown}
        rowId={(row) => row.key}
        columns={columns}
        sort={list.state.sort}
        onSortChange={(sort) => list.setState({ sort })}
        activeId={list.openId}
        rowHref={(row) => list.itemHref(row.key)}
        onRowFollow={(row) => list.open(row.key, "replace")}
        cursorResetKey={`${list.state.status}|${list.state.q}|${list.state.sort?.key ?? ""}:${list.state.sort?.dir ?? ""}`}
        rowDim={(row) => row.kind === "retained" || row.kind === "unavailable" || isMissing(row)}
        loading={data.loading || (data.query.isError && data.query.isFetching)}
        error={
          data.query.isError ? (
            <ErrorState compact title="Couldn’t load credentials" error={data.query.error} onRetry={() => void data.query.refetch()} retrying={data.query.isFetching} />
          ) : undefined
        }
        empty={
          filtered && rows.length > 0 ? (
            <EmptyState
              compact
              icon="search"
              title="No matching credentials"
              actions={
                <Button icon="x" onClick={() => list.setState({ q: "", status: "all" })}>
                  Clear filters
                </Button>
              }
            />
          ) : (
            <EmptyState compact icon="lock" title="No credential connections">
              {subject.administered
                ? "No service this principal is granted needs a credential the principal can store."
                : "No service you are granted needs a credential from you. Services that do appear here."}
            </EmptyState>
          )
        }
        bleed
      />
      {shown.length > 0 ? <ListFooter /> : null}
      {!subject.administered && oauth.isError ? (
        <ErrorState compact title="Couldn’t load OAuth connections" error={oauth.error} onRetry={() => void oauth.refetch()} />
      ) : null}
    </>
  );
}

function confirmRetainedDelete(confirm: ReturnType<typeof useModal>["confirm"], credential: CredentialMetadata, onConfirm: () => Promise<void>) {
  confirm({
    title: "Delete stored credential?",
    body: `Delete the stored ${credential.service}/${credential.name} credential? No service uses it under the current configuration. Its upstream secret is not revoked.`,
    confirmLabel: "Delete credential",
    onConfirm
  });
}

export function CredentialDrawer({ model }: { model: CredentialListModel }) {
  const { open, list } = model;
  if (!open) return null;
  const state = rowState(open);
  const kicker =
    open.kind === "retained" ? (
      <>
        <Icon name="lock" /> Stored credential <span className="wb-num">{open.credential.credentialId}</span>
      </>
    ) : open.kind === "oauth" ? (
      <>
        <Icon name="link" /> OAuth registration <span className="wb-num">{open.oauth.registration}</span>
      </>
    ) : (
      <>
        <Icon name="lock" /> Credential connection <span className="wb-num">{open.connection.connection}</span>
      </>
    );
  return (
    <Drawer
      resetKey={open.key}
      onClose={list.close}
      returnFocus={list.returnFocus}
      label={`${rowName(open)} credential`}
      kicker={kicker}
      title={rowName(open)}
      meta={
        <>
          <StatePill tone={state.tone}>{state.label}</StatePill>
          {open.kind === "token" && open.connection.profile ? <span>{open.connection.profile}</span> : null}
          {open.kind === "retained" ? <span>{open.credential.profile}</span> : null}
        </>
      }
      actions={<DrawerActions model={model} row={open} />}
    >
      <DrawerBody model={model} row={open} />
    </Drawer>
  );
}

function DrawerActions({ model, row }: { model: CredentialListModel; row: CredentialRow }) {
  const { subject, connections } = model;
  const actions = useCredentialActions(subject);
  const writable = canWriteSubject(useSession().session, subject);
  const { confirm } = useModal();
  const runner = useActionRunner();
  if (row.kind === "oauth") return <OAuthConnectionButtons target={row.oauth} connections={connections} />;
  if (row.kind === "retained") {
    return writable ? (
      <Button variant="danger-ghost" icon="trash" onClick={() => confirmRetainedDelete(confirm, row.credential, () => actions.removeRetained(row.credential))}>
        Delete
      </Button>
    ) : null;
  }
  if (row.kind !== "token" || !row.connection.credential || !writable) return null;
  const connection = row.connection;
  // The broker picks the first consumer with an identity probe; Git gateways need a repository below.
  const direct = connection.consumers.some((consumer) => !consumer.credentialVerificationInputs.includes("repository"));
  const services = consumerSummary(connection.consumers, connection.otherConsumers);
  return (
    <>
      {direct ? (
        <Button icon="shield-check" pending={runner.isPending("verify")} onClick={() => void runner.run("verify", () => actions.verify(connection.connection))}>
          Verify
        </Button>
      ) : null}
      <Button
        variant="danger-ghost"
        icon="trash"
        onClick={() =>
          confirm({
            title: "Delete credential?",
            body: `Delete the stored ${connection.displayName} credential? ${services ? `${services} can no longer use it` : "No service can use it"} until a new one is saved. Its upstream secret is not revoked.`,
            confirmLabel: "Delete credential",
            onConfirm: () => actions.remove(connection.connection)
          })
        }
      >
        Delete
      </Button>
    </>
  );
}

function UsedBy({ consumers, otherConsumers, administered }: Pick<CredentialConnection, "consumers" | "otherConsumers"> & { administered: boolean }) {
  const holder = administered ? "this account is" : "you are";
  return (
    <DrawerSection title="Used by">
      {consumers.length ? (
        <ul className="wb-small">
          {consumers.map((consumer) => (
            <li key={consumer.service}>
              {consumer.displayName} <span className="wb-num wb-muted">{consumer.service}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="wb-small wb-muted">No service {holder} granted uses this connection now.</p>
      )}
      {otherConsumers ? <p className="wb-small wb-muted">Also used by {otherConsumers} other {otherConsumers === 1 ? "service" : "services"} {holder} not granted.</p> : null}
    </DrawerSection>
  );
}

function DrawerBody({ model, row }: { model: CredentialListModel; row: CredentialRow }) {
  const { subject, connections } = model;
  const actions = useCredentialActions(subject);
  const writable = canWriteSubject(useSession().session, subject);
  if (row.kind === "oauth") {
    const target = row.oauth;
    return (
      <>
        <DrawerSection title="Account">
          <OAuthConnectionDetails target={target} pending={connections.pending === target.registration} />
        </DrawerSection>
        <UsedBy consumers={target.consumers} otherConsumers={target.otherConsumers} administered={subject.administered} />
        <DrawerSection title="How this works">
          <p className="wb-small wb-fg-2">
            Connecting authorizes the broker for every service using this connection. Disconnecting removes the broker’s copy for all of them; consent at the provider is not removed.
          </p>
        </DrawerSection>
      </>
    );
  }
  if (row.kind === "retained") {
    const credential = row.credential;
    return (
      <>
        <DrawerSection title="Not used">
          <p className="wb-small wb-fg-2">
            The configuration no longer selects this stored credential: its service now uses another connection, its name or profile is retired, or its connection
            uses OAuth for this account. No service reads it. Delete it when it is no longer needed.
          </p>
        </DrawerSection>
        <DrawerSection title="Stored credential">
          <KeyValue
            items={[
              { label: "Stored service", value: <span className="wb-mono">{credential.service}</span> },
              { label: "Name", value: <span className="wb-mono">{credential.name}</span> },
              { label: "Profile", value: <span className="wb-mono">{credential.profile}</span> },
              { label: "Kind", value: <span className="wb-mono">{credential.credentialKind}</span> },
              { label: "Updated", value: <><Time value={credential.updatedAt} format="datetime" /> <span className="wb-muted">by {credential.updatedBy}</span></> }
            ]}
          />
        </DrawerSection>
      </>
    );
  }
  if (row.kind === "unavailable") {
    return (
      <>
        <DrawerSection title="Unavailable">
          <p className="wb-small wb-fg-2">This connection offers no personal credential for this kind of account, so its services cannot run with personal credentials for it.</p>
        </DrawerSection>
        <UsedBy consumers={row.connection.consumers} otherConsumers={row.connection.otherConsumers} administered={subject.administered} />
      </>
    );
  }
  const connection = row.connection;
  const credential = connection.credential;
  const status = credentialStatus(credential);
  return (
    <>
      {credential ? (
        <DrawerSection title="Status">
          <KeyValue
            items={[
              { label: "Status", value: <Badge tone={credentialTone(credential)}>{status}</Badge> },
              { label: "Last checked", value: <Time value={credential.lastVerificationAttemptAt} format="datetime" fallback="Never" /> },
              { label: "Last verified", value: <Time value={credential.lastVerifiedAt} format="datetime" fallback="Never" /> },
              credential.lastVerificationErrorCode ? { label: "Last error", value: <span className="wb-mono">{credential.lastVerificationErrorCode}</span> } : null,
              { label: "Updated", value: <><Time value={credential.updatedAt} format="datetime" /> <span className="wb-muted">by {credential.updatedBy}</span></> },
              { label: "Kind", value: <span className="wb-mono">{credential.credentialKind}</span> }
            ]}
          />
        </DrawerSection>
      ) : null}
      <UsedBy consumers={connection.consumers} otherConsumers={connection.otherConsumers} administered={subject.administered} />
      {writable && credential ? <RepositoryVerification connection={connection} onVerify={(service, repository) => actions.verify(connection.connection, { service, repository })} /> : null}
      {writable && row.target ? (
        <DrawerSection title={credential ? "Replace secret" : "Save a credential"}>
          <CredentialForm key={row.key} target={row.target} replacing={Boolean(credential)} onSave={(values) => actions.save(row.target!, values)} />
        </DrawerSection>
      ) : null}
    </>
  );
}

/** Verification through a Git gateway consumer, against a repository the credential should reach. */
function RepositoryVerification({ connection, onVerify }: { connection: CredentialConnection; onVerify: (service: string, repository: string) => Promise<void> }) {
  const gateways = repositoryConsumers(connection.consumers);
  const runner = useActionRunner();
  const [service, setService] = useState(gateways[0]?.service ?? "");
  const [repository, setRepository] = useState("");
  const first = gateways[0]?.service ?? "";
  // Another connection opening resets the form.
  useEffect(() => {
    setService(first);
    setRepository("");
  }, [connection.connection, first]);
  if (!gateways.length) return null;
  return (
    <DrawerSection title="Verify through Git">
      <form
        className="wb-form-row"
        onSubmit={(event) => {
          event.preventDefault();
          if (service && repository.trim()) void runner.run("verify-repository", () => onVerify(service, repository.trim()));
        }}
      >
        {gateways.length > 1 ? (
          <Field label="Git service">
            <Select value={service} onChange={(event) => setService(event.target.value)}>
              {gateways.map((gateway) => (
                <option key={gateway.service} value={gateway.service}>
                  {gateway.displayName}
                </option>
              ))}
            </Select>
          </Field>
        ) : null}
        <Field label="Repository" hint={`A repository the credential should reach through ${gateways.find((gateway) => gateway.service === service)?.displayName ?? "the Git gateway"}, as namespace/repository.`}>
          <Input mono value={repository} onChange={(event) => setRepository(event.target.value)} placeholder="namespace/repository" autoCapitalize="none" spellCheck={false} />
        </Field>
        <Button type="submit" icon="shield-check" disabled={!repository.trim()} pending={runner.isPending("verify-repository")}>
          Verify
        </Button>
      </form>
    </DrawerSection>
  );
}

/** Secret entry for one connection's token; values never leave this form except in the save request. */
function CredentialForm({ target, replacing, onSave }: { target: CredentialTarget; replacing: boolean; onSave: (values: Record<string, string>) => Promise<void> }) {
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(target.inputSchema.fields.map((field) => [field.name, ""])));
  const [visible, setVisible] = useState<Record<string, boolean>>({});
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dirty = Object.values(values).some(Boolean);
  const missing = target.inputSchema.fields.some((field) => field.required && !values[field.name]);
  return (
    <form
      className="wb-form-stack"
      autoComplete="off"
      onSubmit={async (event) => {
        event.preventDefault();
        if (missing || !dirty) return;
        setPending(true);
        setError(null);
        try {
          await onSave(values);
          setValues(Object.fromEntries(target.inputSchema.fields.map((field) => [field.name, ""])));
        } catch (failure) {
          setError(errorMessage(failure));
        } finally {
          setPending(false);
        }
      }}
    >
      {target.inputSchema.fields.map((field) => {
        const hidden = field.secret && !visible[field.name];
        return (
          <Field key={field.name} label={field.prompt} hint={field.description} optional={!field.required}>
            <div className="flex gap-2">
              <Input
                type={hidden && !MASKED_TEXT_SECURITY_SUPPORTED ? "password" : "text"}
                className={hidden && MASKED_TEXT_SECURITY_SUPPORTED ? "pt-secret flex-1" : "flex-1"}
                value={values[field.name] ?? ""}
                onChange={(event) => setValues({ ...values, [field.name]: event.target.value })}
                required={field.required}
                autoComplete={field.secret ? "new-password" : "off"}
                autoCapitalize="none"
                spellCheck={false}
                data-lpignore="true"
                data-1p-ignore="true"
                data-bwignore="true"
              />
              {field.secret ? (
                <IconButton
                  variant="default"
                  icon={visible[field.name] ? "eye-off" : "eye"}
                  label={`${visible[field.name] ? "Hide" : "Show"} ${field.prompt}`}
                  onClick={() => setVisible({ ...visible, [field.name]: !visible[field.name] })}
                />
              ) : null}
            </div>
          </Field>
        );
      })}
      <FormError error={error} />
      <div className="flex justify-end">
        <Button type="submit" variant="primary" disabled={missing || !dirty} pending={pending}>
          {replacing ? "Replace credential" : "Save credential"}
        </Button>
      </div>
    </form>
  );
}
