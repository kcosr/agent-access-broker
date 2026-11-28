// Issue access key: a full page, for the signed-in person (from their own
// options) or for an account an administrator opened (from the account's
// resolved access key type policy and the configured types). No access type
// is chosen for the person, also when one type is offered.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useBlocker, useNavigate, useParams } from "react-router";
import type { AccessKeyType } from "../../types";
import { ApiError } from "../../api";
import {
  accessKeyAccountProblem,
  accessKeyLifetimeChoices,
  accessKeyLifetimeHint,
  accessKeyLifetimeLabel,
  accessKeyRefusalMessage,
  accessKeysShown,
  accessKeyTypeLabels,
  administeredAccessKeyTypes,
  administeredIssueBlocker,
  buildAccessKeyIssue,
  canIssueOwnAccessKey,
  newAccessKeyDraft,
  offeredAccessKeyLifetime,
  ownAccessKeyBlocker,
  reconcileAccessKeyLifetime,
  selfServiceTypes,
  toggleAccessKeyType,
  unavailableChoices,
  type AccessKeyDraft,
  type AccessKeyDraftField
} from "../../lib/access-keys";
import { errorMessage, identityDisplayName } from "../../lib/helpers";
import { canWriteAdmin } from "../../lib/capabilities";
import { AppLink, Button, Card, Checkbox, Chip, EmptyState, ErrorState, Field, Icon, Input, KeyValue, List, Main, PageHeader, plural, Select, SkeletonBlock } from "../../workbench";
import { DiscardChangesDialog } from "../../components/discard-changes-dialog";
import { FormError } from "../../components/form";
import { type AccountSubject } from "../../app/active-route";
import { useModal } from "../../app/modal";
import { NotFoundPage } from "../../app/gate";
import { paths } from "../../app/paths";
import { useSession } from "../../app/session";
import { PortalPage } from "../../app/top-bar";
import { useAccessKeysOffered, useAdminAccessKeyTypes, useAdminPrincipal, useOwnAccessKeyOptions } from "../../data/queries";
import { useAccessKeyActions } from "../../mutations/access-keys";
import { KEYS_DESCRIPTION } from "./keys-page";

const listPath = (subject: AccountSubject, key?: string) => (subject.administered ? paths.principalAccessKeys(subject.principalId, key) : paths.accessKeys(key));
const fieldId = (field: AccessKeyDraftField) => `access-key-${field}`;

type IssueContext = {
  subject: AccountSubject;
  offered: AccessKeyType[];
  /** Types the account may not hold: an administrator sees which, and where to change it. */
  notOffered: AccessKeyType[];
  username: string;
  ownerName: string;
  header: ReactNode;
  back: string;
};

export function AccessKeyIssuePage() {
  const { principalId } = useParams();
  return principalId === undefined ? <OwnIssuePage /> : <AdministeredIssuePage principalId={principalId} />;
}

function Frame({ title, header, children }: { title: string; header: ReactNode; children: ReactNode }) {
  return <PortalPage><Main label={title}>{header}<List>{children}</List></Main></PortalPage>;
}

/**
 * What decides issuing could not be read again: the form keeps the draft and
 * refuses to issue until a read succeeds.
 */
type Unavailable = { title: string; status: string; error: unknown; retry: () => void; retrying: boolean } | null;

function OwnIssuePage() {
  const { session } = useSession();
  const subject: AccountSubject = { administered: false, principalId: session.principal ?? "" };
  const offered = useAccessKeysOffered(true, true);
  const options = useOwnAccessKeyOptions(offered.data === true, true);
  // Once a form has started, a failed read keeps the draft instead of replacing it.
  const started = useRef(false);
  const back = paths.accessKeys();
  const header = <PageHeader title="Issue access key" back={{ href: back, label: "Access keys" }} meta={`${KEYS_DESCRIPTION} The broker itself does not accept access keys.`} />;
  const failing = offered.isError || options.isError;
  const error = offered.isError ? offered.error : options.error;
  const retry = () => { void offered.refetch(); void options.refetch(); };
  if (offered.isSuccess && offered.data === false) return <NotFoundPage />;
  if (options.isSuccess && !accessKeysShown(options.data)) return <NotFoundPage />;
  // A fresh form waits for options read successfully on this visit, never a cached copy.
  const ready = offered.isSuccess && options.isSuccess && options.isFetchedAfterMount;
  if (!options.data || (!started.current && !ready)) {
    started.current = false;
    return <Frame title="Issue access key" header={header}>{failing ? <ErrorState title="Couldn’t load your access key options" error={error} onRetry={retry} /> : <SkeletonBlock lines={8} label="Loading access key options" />}</Frame>;
  }
  if (!failing) {
    const blocker = ownAccessKeyBlocker(options.data);
    if (blocker || !canIssueOwnAccessKey(options.data)) {
      started.current = false;
      return <Frame title="Issue access key" header={header}><EmptyState icon="key" title="You cannot issue an access key now" actions={<Button href={back} icon="arrow-left">Back to access keys</Button>}>{blocker ?? "No access key type is one you can issue yourself."}</EmptyState></Frame>;
    }
  }
  started.current = true;
  const unavailable: Unavailable = failing
    ? { title: "Couldn’t refresh your access key options", status: "Your access key options could not be refreshed.", error, retry, retrying: offered.isFetching || options.isFetching }
    : options.isFetching ? { title: "", status: "Refreshing your access key options.", error: null, retry, retrying: true } : null;
  return (
    <AccessKeyEditor
      key={subject.principalId}
      unavailable={unavailable}
      context={{ subject, offered: selfServiceTypes(options.data), notOffered: [], username: options.data.accountUsername?.name ?? "", ownerName: identityDisplayName(session.displayName) || subject.principalId, header, back }}
    />
  );
}

function AdministeredIssuePage({ principalId }: { principalId: string }) {
  const { session } = useSession();
  const subject: AccountSubject = { administered: true, principalId };
  // The form starts from what the server says now, never from a cached copy.
  const owner = useAdminPrincipal(principalId, true, true);
  const types = useAdminAccessKeyTypes(true, true);
  const started = useRef(false);
  const back = paths.principalAccessKeys(principalId);
  const detail = owner.data;
  const ownerName = identityDisplayName(detail?.displayName) || principalId;
  const meta = detail?.kind === "service_account" || ownerName === principalId ? `For ${principalId}` : `For ${ownerName} · ${principalId}`;
  const header = <PageHeader title="Issue access key" back={{ href: back, label: "Keys" }} meta={meta} />;
  const failing = owner.isError || types.isError;
  const error = owner.isError ? owner.error : types.error;
  const retry = () => { void owner.refetch(); void types.refetch(); };
  if (!canWriteAdmin(session)) return <NotFoundPage />;
  const ready = owner.isSuccess && owner.isFetchedAfterMount && types.isSuccess && types.isFetchedAfterMount;
  if (!detail || !types.data || (!started.current && !ready)) {
    started.current = false;
    return <Frame title="Issue access key" header={header}>{failing ? <ErrorState title="Couldn’t load the account’s access key types" error={error} onRetry={retry} /> : <SkeletonBlock lines={8} label="Loading access key types" />}</Frame>;
  }
  const { offered, notOffered } = administeredAccessKeyTypes(types.data, detail.accessKeyTypePolicy);
  if (!failing) {
    // Why no key of the account can work, as the server states it, comes
    // first; then what this form needs: an account that holds keys, and a type.
    // Each reason names the tab that fixes it, if any.
    const blocker = accessKeyAccountProblem(detail) ?? administeredIssueBlocker({ kind: detail.kind, offered: offered.length });
    if (blocker) {
      started.current = false;
      const { fix } = blocker;
      return <Frame title="Issue access key" header={header}><EmptyState icon="key" title="An access key cannot be issued for this account now" actions={<><Button href={back} icon="arrow-left">Back to keys</Button>{fix === "overview" ? <Button href={paths.principal(principalId)}>Open Overview</Button> : fix === "groups" ? <Button href={paths.principal(principalId, "groups")}>Open Groups</Button> : null}</>}>{blocker.text}</EmptyState></Frame>;
    }
  }
  started.current = true;
  const unavailable: Unavailable = failing
    ? { title: "Couldn’t refresh the account’s access key types", status: "The account’s access key types could not be refreshed.", error, retry, retrying: owner.isFetching || types.isFetching }
    : owner.isFetching || types.isFetching ? { title: "", status: "Refreshing the account’s access key types.", error: null, retry, retrying: true } : null;
  return (
    <AccessKeyEditor
      key={principalId}
      unavailable={unavailable}
      context={{ subject, offered, notOffered, username: detail.accountUsername?.name?.accountUsername ?? "", ownerName, header, back }}
    />
  );
}

function AccessKeyEditor({ context, unavailable }: { context: IssueContext; unavailable: Unavailable }) {
  const { subject, offered, notOffered, username, ownerName, header, back } = context;
  const { getSession } = useSession();
  const { setModal } = useModal();
  const actions = useAccessKeyActions(subject);
  const navigate = useNavigate();
  const [initial] = useState(() => newAccessKeyDraft());
  // Every type offered during this draft, to name a choice that is no longer offered.
  const seen = useRef(new Map<string, AccessKeyType>());
  for (const type of offered) seen.current.set(type.id, type);
  const [draft, setDraft] = useState<AccessKeyDraft>(initial);
  useEffect(() => { setDraft((current) => reconcileAccessKeyLifetime(current, offered)); }, [offered]);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<{ message: string; lifetime?: string } | null>(null);
  // A refreshed choice follows the same preselection rule as a type change.
  // Keep a refusal only while it still describes the selected lifetime.
  useEffect(() => {
    setError((current) => current?.lifetime !== undefined && offeredAccessKeyLifetime([current.lifetime], draft.lifetime) === null ? null : current);
  }, [draft.lifetime]);
  const done = useRef(false);
  // Set before the first await, so a second activation in the same moment sends nothing.
  const submitting = useRef(false);
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  const request = buildAccessKeyIssue(draft, offered);
  const issues = request.valid ? [] : request.issues;
  const blocker = useBlocker(({ currentLocation, nextLocation }) => {
    const current = getSession();
    return current.authenticated && !current.passwordChangeRequired && !done.current && (submitting.current || pending || dirty)
      && (currentLocation.pathname !== nextLocation.pathname || currentLocation.search !== nextLocation.search);
  });
  useEffect(() => { if (pending && blocker.state === "blocked") blocker.reset(); }, [pending, blocker]);
  // Closing or reloading the browser page while issuing would lose the key: ask first.
  useEffect(() => {
    if (!pending) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [pending]);

  function update(next: AccessKeyDraft) {
    if (pending || submitting.current) return;
    setError(null);
    setDraft(next);
  }

  function reveal(field: AccessKeyDraftField) {
    requestAnimationFrame(() => {
      const element = document.getElementById(fieldId(field));
      element?.scrollIntoView({ block: "center", behavior: "smooth" });
      element?.querySelector<HTMLElement>("input:not(:disabled), select:not(:disabled)")?.focus({ preventScroll: true });
    });
  }

  async function issue() {
    if (submitting.current || pending || unavailable || !request.valid) return;
    submitting.current = true;
    setPending(true);
    setError(null);
    try {
      const { issued, viewer } = await actions.issue(request.body);
      done.current = true;
      const current = getSession();
      const destination = listPath(subject, issued.record.keyId);
      // The key is shown only to the person who issued it, still signed in,
      // and only on the list it lands on: leaving that page ends the dialog.
      if (viewer && current.authenticated && current.principal === viewer && !current.passwordChangeRequired) {
        setModal({ type: "accessKeyReveal", key: issued.key, record: issued.record, username, ownerName, typeLabels: accessKeyTypeLabels(offered, issued.record.accessKeyTypes), destination: new URL(destination, window.location.origin).pathname, viewerPrincipal: viewer });
      }
      blocker.reset?.();
      navigate(destination, { replace: true });
    } catch (failure) {
      // A refused mint carries the reason; a key committed without its audit
      // record is never shown, so the list is the place to look.
      const refusal = failure instanceof ApiError ? accessKeyRefusalMessage(failure.details?.refusal, !subject.administered) : null;
      const unavailable = failure instanceof ApiError && failure.reasonCode === "audit_unavailable";
      setError({
        message: unavailable ? "The broker could not record the issue, so the key is not shown. Check the access key list before trying again." : refusal ?? errorMessage(failure),
        ...(failure instanceof ApiError && failure.details?.refusal === "lifetime_not_offered" ? { lifetime: request.body.lifetime } : {})
      });
      actions.refresh();
    } finally {
      submitting.current = false;
      setPending(false);
    }
  }

  const choices = accessKeyLifetimeChoices(offered, draft.accessKeyTypes);
  const selectedLifetime = offeredAccessKeyLifetime(choices, draft.lifetime);
  const lifetimeOptions = [
    ...(choices.length && selectedLifetime === null ? [{ value: "", label: "Choose a lifetime", disabled: true }] : []),
    ...choices.map((lifetime) => ({ value: lifetime, label: accessKeyLifetimeLabel(lifetime) }))
  ];
  const chosenNames = accessKeyTypeLabels(offered, draft.accessKeyTypes);
  const status = pending ? (
    <span>Issuing the access key. Wait for it to finish before leaving this page.</span>
  ) : unavailable ? (
    <><Icon name="alert-circle" /><span>{unavailable.status}</span></>
  ) : issues.length ? (
    <>
      <Icon name="alert-circle" />
      <span><b>{issues.length} {plural(issues.length, "issue")}</b> · <button type="button" className="wb-link" onClick={() => reveal(issues[0]!.field)}>{issues[0]!.message}</button></span>
    </>
  ) : (
    <><Icon name="circle-check" /><span>Ready to issue. An access key cannot be edited after it is issued.</span></>
  );
  const footer = (
    <div className={`wb-draftbar pt-token-draftbar${(issues.length || unavailable?.error) && !pending ? "" : " wb-draftbar--neutral"}`} role="region" aria-label="Issue access key">
      <div className="pt-validation" role="status">{status}</div>
      <div className="wb-draftbar-actions">
        <Button onClick={() => navigate(back)} disabled={pending}>Cancel</Button>
        <Button variant="primary" onClick={() => void issue()} pending={pending} disabled={pending || Boolean(unavailable) || !request.valid}>Issue access key</Button>
      </div>
    </div>
  );
  const usernameLine = <span className="wb-mono">{username}</span>;
  return (
    <PortalPage>
      <Main label="Issue access key" footer={footer} tint>
        {header}
        <div className="pt-editor pt-token-editor pt-key-editor">
          <div className="pt-token-form">
            {unavailable?.error ? <ErrorState compact title={unavailable.title} error={unavailable.error} onRetry={unavailable.retry} retrying={unavailable.retrying} /> : null}
            <Card id={fieldId("access")} title="Access" subtitle={subject.administered ? "Only access this account is allowed is offered, including types people cannot issue themselves." : "An administrator decides which kinds of access you can choose."}>
              <fieldset className="pt-fieldset pt-fieldset--plain pt-card-body" disabled={pending}>
                <legend>This key gives access to:</legend>
                <div className="pt-key-types">
                  {offered.map((type) => (
                    <Checkbox
                      key={type.id}
                      label={type.displayName}
                      description={<>
                        {type.description ? <span className="pt-key-type-line">{type.description}</span> : null}
                        <span className="pt-key-type-line">Lifetimes: {type.lifetimeOptions.map(accessKeyLifetimeLabel).join(", ")}. Default: {accessKeyLifetimeLabel(type.defaultLifetime)}.{subject.administered && !type.selfService ? " People cannot issue it themselves." : ""}</span>
                      </>}
                      checked={draft.accessKeyTypes.includes(type.id)}
                      onChange={(event) => update(toggleAccessKeyType(draft, type.id, event.target.checked, offered))}
                    />
                  ))}
                </div>
                {unavailableChoices(draft, offered, seen.current).map((choice) => (
                  <Checkbox
                    key={choice.id}
                    label={choice.label}
                    description={subject.administered ? "No longer allowed for this account. Remove it to issue this key." : "No longer offered to you. Remove it to issue this key."}
                    checked
                    onChange={(event) => update(toggleAccessKeyType(draft, choice.id, event.target.checked, offered))}
                  />
                ))}
                {subject.administered && notOffered.length ? (
                  <p className="wb-field-hint">Not offered, because {ownerName} is not allowed them: {notOffered.map((type) => type.displayName).join(", ")}. <AppLink className="wb-link" href={paths.principal(subject.principalId)}>Open the Access key types setting on the Overview tab</AppLink></p>
                ) : (
                  <p className="wb-field-hint">{subject.administered ? "Choose one or more." : "Choose one or more. Kinds of access you cannot use are not shown."}</p>
                )}
              </fieldset>
            </Card>
            <Card title="Details" subtitle="Name the key and choose how long it lasts.">
              <div className="pt-card-body">
                <div className="pt-token-details-row">
                  <div id={fieldId("name")}>
                    <Field label="Name" hint={subject.administered ? "Where the key runs, for example “ci-cache” or “eval-notebook”." : "Where the key runs, for example “laptop-models” or “eval-notebook”."}>
                      <Input value={draft.name} onChange={(event) => update({ ...draft, name: event.target.value })} required disabled={pending} autoFocus />
                    </Field>
                  </div>
                  <div id={fieldId("lifetime")}>
                    <Field label="Lifetime" hint={accessKeyLifetimeHint(offered, draft.accessKeyTypes)}>
                      <Select value={selectedLifetime ?? ""} onChange={(event) => update({ ...draft, lifetime: event.target.value, lifetimeManuallyChosen: true })} disabled={pending || choices.length === 0} options={lifetimeOptions} />
                    </Field>
                  </div>
                </div>
                {subject.administered ? (
                  <div className="wb-field">
                    <span className="wb-field-label">Owner</span>
                    <p className="pt-key-value">{ownerName}</p>
                    <div className="wb-field-hint">The key will belong to this account, and services will know it as {usernameLine}. It is shown once, when it is issued; pass it on yourself.</div>
                  </div>
                ) : (
                  <div className="wb-field">
                    <span className="wb-field-label">Username</span>
                    <p className="pt-key-value wb-mono">{username}</p>
                    <div className="wb-field-hint">Services behind the gateway know you by this name and record what the key is used for under it. It is set on your account.</div>
                  </div>
                )}
                <FormError error={error?.message ?? null} />
              </div>
            </Card>
          </div>
          <aside className="pt-token-summary" aria-label="Access key summary">
            <Card title="Summary">
              <div className="pt-card-body">
                <KeyValue labelWidth={100} items={[
                  subject.administered ? { label: "Owner", value: ownerName } : null,
                  { label: "Gives access to", value: chosenNames.length ? <span className="wb-inline pt-key-pills pt-key-pills--wrap">{chosenNames.map((item) => <Chip key={item.id}>{item.label}</Chip>)}</span> : <span className="wb-muted">Nothing chosen yet</span> },
                  { label: "Name", value: draft.name.trim() || <span className="wb-muted">Not named yet</span> },
                  { label: "Lifetime", value: selectedLifetime === null ? <span className="wb-muted">Not chosen</span> : accessKeyLifetimeLabel(selectedLifetime) },
                  { label: "Username", value: usernameLine }
                ]} />
                <p className="pt-prose">An access key is fixed once issued; issue a replacement to change it.</p>
              </div>
            </Card>
          </aside>
        </div>
      </Main>
      <DiscardChangesDialog blocker={blocker} open={blocker.state === "blocked" && !pending}><p>Your access key has not been issued.</p></DiscardChangesDialog>
    </PortalPage>
  );
}

