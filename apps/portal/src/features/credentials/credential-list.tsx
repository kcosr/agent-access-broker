import { canWriteSubject } from "../../lib/capabilities";
import { useSession } from "../../app/session";
// Upstream credentials for the signed-in user (My access › Credentials) or an
// administered principal (the user page's Credentials tab): rows per target,
// a drawer to set, replace, verify, or delete, and Connected accounts (self).
import { useEffect, useId, useMemo, useState } from "react";
import type { CredentialMetadata, CredentialTarget } from "../../types";
import { MASKED_TEXT_SECURITY_SUPPORTED, credentialStatus, credentialTone, credentialsByTarget, errorMessage } from "../../lib/helpers";
import { serviceDisplayNames } from "../../lib/access";
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
  GroupHeader,
  Icon,
  IconButton,
  Input,
  KeyValue,
  ListFooter,
  plural,
  Seg,
  StateCell,
  StatePill,
  Time,
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
import { credentialVerificationNeedsRepository, useCredentialActions } from "../../mutations/credentials";
import { FormError } from "../../components/form";
import { OAuthConnectionsTable, useOAuthConnectionActions } from "../../components/oauth-connections";

const FILTERS = ["all", "attention", "missing"] as const;

export const CREDENTIAL_STATE = {
  status: urlParam.oneOf(FILTERS, "all"),
  sort: urlParam.sort(["service", "verified"]),
  q: urlParam.text(),
  credential: urlParam.text()
};

const targetKey = (target: CredentialTarget) => `${target.service}/${target.credentialName}`;

function needsAttention(credential: CredentialMetadata | undefined) {
  const status = credentialStatus(credential);
  return status === "Not verified" || status === "Verification failed";
}

export function useCredentialList(subject: AccountSubject) {
  const data = useConsoleData(subject);
  const oauth = useOAuthConnections(!subject.administered);
  const byTarget = useMemo(() => credentialsByTarget(data.credentials), [data.credentials]);
  // Names come with the credential targets, whatever the request's execution context.
  const names = useMemo(() => serviceDisplayNames(null, data.targets), [data.targets]);
  const displayName = (service: string) => names.get(service) ?? service;
  const filter = (state: { status: (typeof FILTERS)[number]; q: string }) => {
    const query = state.q.trim().toLowerCase();
    return data.targets.filter((target) => {
      const credential = byTarget.get(targetKey(target));
      if (state.status === "attention" && !needsAttention(credential)) return false;
      if (state.status === "missing" && credential) return false;
      return !query || `${targetKey(target)} ${displayName(target.service)} ${target.profile}`.toLowerCase().includes(query);
    });
  };
  const list = useTableUrlState(CREDENTIAL_STATE, "credential");
  const shown = sortRows(
    filter(list.state),
    list.state.sort,
    (target, key) => (key === "verified" ? byTarget.get(targetKey(target))?.lastVerifiedAt : displayName(target.service)),
    (a, b) => displayName(a.service).localeCompare(displayName(b.service)) || targetKey(a).localeCompare(targetKey(b))
  );
  const counts = {
    all: data.targets.length,
    attention: data.targets.filter((target) => needsAttention(byTarget.get(targetKey(target)))).length,
    missing: data.targets.filter((target) => !byTarget.has(targetKey(target))).length
  };
  const open = list.openId ? data.targets.find((target) => targetKey(target) === list.openId) ?? null : null;
  return { subject, data, oauth, byTarget, displayName, list, shown, counts, open };
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
            { value: "missing", label: "Not saved", count: counts.missing }
          ]}
        />
        <FilterInput value={list.state.q} onChange={(q) => list.setState({ q })} placeholder="Filter credentials…" debounceMs={150} />
        <ToolbarSummary grow>
          <b>{counts.all - counts.missing}</b> of {counts.all} saved
        </ToolbarSummary>
      </ToolbarRow>
    </Toolbar>
  );
}

export function CredentialRows({ model }: { model: CredentialListModel }) {
  const { data, oauth, list, shown, byTarget, displayName, subject } = model;
  const connections = useOAuthConnectionActions("/ui/credentials");
  const accountsHeading = useId();
  const targets = oauth.data ?? [];
  const filtered = Boolean(list.state.q || list.state.status !== "all");
  const columns = useMemo<DataColumn<CredentialTarget>[]>(
    () => [
      {
        key: "status",
        header: "Status",
        cell: (target) => {
          const credential = byTarget.get(targetKey(target));
          const status = credentialStatus(credential);
          return <StateCell label={status} tone={credential ? credentialTone(credential) : "muted"} quiet={status === "Upstream verified" || status === "Local verified"} />;
        }
      },
      { key: "service", header: "Service", primary: true, sortable: true, truncate: true, minWidth: "14ch", cell: (target) => displayName(target.service) },
      { key: "credential", header: "Credential", priority: 2, truncate: true, minWidth: "14ch", className: "wb-cell-mono", cell: (target) => targetKey(target) },
      { key: "profile", header: "Profile", priority: 4, truncate: true, minWidth: "10ch", className: "wb-cell-muted", cell: (target) => target.profile },
      {
        key: "error",
        header: "Last error",
        priority: 3,
        className: "wb-cell-mono",
        // Only a credential whose verification failed has one.
        hideWhenEmpty: true,
        cell: (target) => {
          const credential = byTarget.get(targetKey(target));
          return credential && credentialStatus(credential) === "Verification failed" ? credential.lastVerificationErrorCode ?? "" : "";
        }
      },
      {
        key: "verified",
        header: "Verified",
        sortable: true,
        firstSortDir: "desc",
        priority: 2,
        cell: (target) => {
          const credential = byTarget.get(targetKey(target));
          return credential?.lastVerifiedAt ? <Time value={credential.lastVerifiedAt} /> : <span className="wb-muted">{credential ? "Never" : ""}</span>;
        }
      },
      {
        key: "saved",
        header: "Saved",
        priority: 3,
        cell: (target) => {
          const credential = byTarget.get(targetKey(target));
          return credential ? <Time value={credential.updatedAt} /> : null;
        }
      }
    ],
    [byTarget, displayName]
  );
  return (
    <>
      <DataTable
        label="Service credentials"
        rows={shown}
        rowId={targetKey}
        columns={columns}
        sort={list.state.sort}
        onSortChange={(sort) => list.setState({ sort })}
        activeId={list.openId}
        rowHref={(target) => list.itemHref(targetKey(target))}
        onRowFollow={(target) => list.open(targetKey(target), "replace")}
        cursorResetKey={`${list.state.status}|${list.state.q}|${list.state.sort?.key ?? ""}:${list.state.sort?.dir ?? ""}`}
        rowDim={(target) => !byTarget.has(targetKey(target))}
        loading={data.loading || (data.query.isError && data.query.isFetching)}
        error={
          data.query.isError ? (
            <ErrorState compact title="Couldn’t load credentials" error={data.query.error} onRetry={() => void data.query.refetch()} retrying={data.query.isFetching} />
          ) : undefined
        }
        empty={
          filtered && data.targets.length > 0 ? (
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
            <EmptyState compact icon="lock" title="No per-user credentials">
              {subject.administered ? "No service needs a per-user credential for this principal." : "No service needs a credential from you. Services that do appear here."}
            </EmptyState>
          )
        }
        bleed
      />
      {shown.length > 0 ? <ListFooter /> : null}
      {!subject.administered && targets.length > 0 ? (
        <section aria-labelledby={accountsHeading}>
          <GroupHeader id={accountsHeading} title="Connected accounts" count={`${targets.length} ${plural(targets.length, "service")}`} sticky={false} />
          <OAuthConnectionsTable targets={targets} connections={connections} />
        </section>
      ) : null}
      {!subject.administered && oauth.isError ? <ErrorState compact title="Couldn’t load connected accounts" error={oauth.error} onRetry={() => void oauth.refetch()} /> : null}
    </>
  );
}

export function CredentialDrawer({ model }: { model: CredentialListModel }) {
  const { open, byTarget, displayName, list, subject } = model;
  const actions = useCredentialActions(subject);
  const writable = canWriteSubject(useSession().session, subject);
  const { confirm } = useModal();
  const runner = useActionRunner();
  const [repository, setRepository] = useState("");
  useEffect(() => setRepository(""), [open]);
  if (!open) return null;
  const key = targetKey(open);
  const credential = byTarget.get(key);
  const status = credentialStatus(credential);
  const needsRepository = credentialVerificationNeedsRepository(open);
  return (
    <Drawer
      resetKey={key}
      onClose={list.close}
      returnFocus={list.returnFocus}
      label={`${displayName(open.service)} credential`}
      kicker={
        <>
          <Icon name="lock" /> Credential <span className="wb-num">{key}</span>
        </>
      }
      title={displayName(open.service)}
      meta={
        <>
          <StatePill tone={credentialTone(credential)}>{status}</StatePill>
          <span>{open.profile}</span>
        </>
      }
      actions={
        credential && writable ? (
          <>
            {!needsRepository ? (
              <Button icon="shield-check" pending={runner.isPending("verify")} onClick={() => void runner.run("verify", () => actions.verify(open))}>
                Verify
              </Button>
            ) : null}
            <Button
              variant="danger-ghost"
              icon="trash"
              onClick={() =>
                confirm({
                  title: "Delete credential?",
                  body: `Delete ${key}? The stored secret is removed and actions that need it fail until a new one is saved.`,
                  confirmLabel: "Delete credential",
                  onConfirm: () => actions.remove(open)
                })
              }
            >
              Delete
            </Button>
          </>
        ) : null
      }
    >
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
      {writable && credential && needsRepository ? (
        <DrawerSection title="Verify">
          <form
            className="pt-inline-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (repository.trim()) void runner.run("verify", () => actions.verify(open, { repository: repository.trim() }));
            }}
          >
            <Field label="Repository" hint="A repository the credential should reach, as namespace/repository.">
              <Input mono value={repository} onChange={(event) => setRepository(event.target.value)} placeholder="namespace/repository" autoCapitalize="none" spellCheck={false} />
            </Field>
            <Button type="submit" icon="shield-check" disabled={!repository.trim()} pending={runner.isPending("verify")}>
              Verify
            </Button>
          </form>
        </DrawerSection>
      ) : null}
      {writable ? <DrawerSection title={credential ? "Replace secret" : "Save a credential"}>
        <CredentialForm key={key} target={open} replacing={Boolean(credential)} onSave={(values) => actions.save(open, values)} />
      </DrawerSection> : null}
    </Drawer>
  );
}

/** Secret entry for one credential target; values never leave this form except in the save request. */
function CredentialForm({ target, replacing, onSave }: { target: CredentialTarget; replacing: boolean; onSave: (values: Record<string, string>) => Promise<void> }) {
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(target.inputSchema.fields.map((field) => [field.name, ""])));
  const [visible, setVisible] = useState<Record<string, boolean>>({});
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dirty = Object.values(values).some(Boolean);
  const missing = target.inputSchema.fields.some((field) => field.required && !values[field.name]);
  return (
    <form
      className="pt-form"
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
