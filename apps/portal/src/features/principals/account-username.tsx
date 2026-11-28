// A person's username on their Overview: From email (the server's value for
// the saved email, read-only) or Set by hand, its state, and the result of
// the last change. The page never works out a name: it shows what the
// server returns, and nothing for an email that has not been saved.
import { useEffect, useState } from "react";
import type { AccountUsernameMode, PrincipalAccountUsername, PrincipalDetail } from "../../types";
import { canWriteAdmin } from "../../lib/capabilities";
import { errorMessage, identityDisplayName } from "../../lib/helpers";
import { fromEmailExplanation, usernameChangeSummary, usernameChangeWarning, usernameReasonText, usernameStateBadge } from "../../lib/access-keys";
import { AppLink, Badge, Banner, Input, KeyValue, Seg, SettingsRow, SettingsSection, Time } from "../../workbench";
import { AdminButton, AdminOnly } from "../../components/admin-access";
import { FormError } from "../../components/form";
import { useModal } from "../../app/modal";
import { paths } from "../../app/paths";
import { useSession } from "../../app/session";
import { useAdminPrincipals } from "../../data/queries";
import { useAccountUsernameActions } from "../../mutations/access-keys";

/**
 * What the last saved change did, from the server; shown in the section whose
 * save made it (`profile` for an email, `username` for the name or mode)
 * until dismissed or the next change.
 */
export type UsernameNotice = { principalId: string; source: "profile" | "username"; text: string; changed: boolean } | null;

export function UsernameChangeNotice({ notice, principalId, source, onDismiss }: { notice: UsernameNotice; principalId: string; source: "profile" | "username"; onDismiss: () => void }) {
  if (!notice || notice.principalId !== principalId || notice.source !== source) return null;
  return <Banner tone={notice.changed ? "warning" : "info"} live onDismiss={onDismiss} title="Username after the change">{notice.text}</Banner>;
}

const SYSTEM_ACTORS: Record<string, string> = {
  "system:sign_in": "at sign-in",
  "system:startup": "at startup",
  "system:reload": "at a configuration reload"
};

function assignedByText(actor: string) {
  return Object.hasOwn(SYSTEM_ACTORS, actor) ? SYSTEM_ACTORS[actor] : `by ${actor}`;
}

export function UsernameHistory({ username }: { username: PrincipalAccountUsername }) {
  const name = username.name;
  const confirmation = username.state === "awaiting_confirmation" ? "Awaiting an administrator"
    : name?.confirmedAt ? <><Time value={name.confirmedAt} format="datetime" /> <span className="wb-muted">confirmed by {name.confirmedBy ?? "unknown"}</span></>
    : name === null ? "Not applicable" : "Not required";
  const keys = username.liveKeys > 0 ? `${username.liveKeys} active` : username.state === "usable" ? "None" : "None; issuing is blocked";
  return (
    <KeyValue
      items={[
        { label: "Last changed", value: name ? <><Time value={name.assignedAt} format="datetime" /> <span className="wb-muted">{assignedByText(name.assignedBy)}{name.origin === "derived" ? ", from the email" : name.origin === "administrator" ? ", set by hand" : ""}</span></> : "Never set" },
        { label: "Confirmation", value: confirmation },
        { label: "Access keys", value: keys }
      ]}
    />
  );
}

export function AccountUsernameSection({ principal, notice, setNotice }: { principal: PrincipalDetail; notice: UsernameNotice; setNotice: (notice: UsernameNotice) => void }) {
  const username = principal.accountUsername!;
  const { session } = useSession();
  const { confirm } = useModal();
  const actions = useAccountUsernameActions(principal.principalId);
  const principals = useAdminPrincipals().data;
  const writable = canWriteAdmin(session);
  const held = username.name?.accountUsername ?? "";
  const savedMode: AccountUsernameMode = username.mode ?? "from_email";
  const [mode, setMode] = useState<AccountUsernameMode>(savedMode);
  const [typed, setTyped] = useState(held);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // A saved change or a refetch replaces the draft with what the server holds now.
  const savedKey = `${principal.principalId}|${savedMode}|${username.name?.incarnation ?? ""}`;
  useEffect(() => {
    setMode(savedMode);
    setTyped(held);
    setError(null);
  }, [savedKey]);
  const who = identityDisplayName(principal.displayName) || principal.principalId;
  const badge = usernameStateBadge(username.state);
  const typedName = typed.trim();
  const dirty = mode !== savedMode || (mode === "manual" && typedName !== held);
  const fromEmail = username.fromEmail?.accountUsername ?? null;
  const holder = username.conflict ? principals?.find((item) => item.principalId === username.conflict!.heldBy) : undefined;

  function body() {
    if (mode === "from_email") return { mode: "from_email" as const };
    if (typedName === held && savedMode === "from_email") return { mode: "manual" as const };
    return { mode: "manual" as const, accountUsername: typedName || null };
  }

  function save() {
    confirm({
      title: "Save the username?",
      body: usernameChangeWarning(who, username.liveKeys),
      confirmLabel: "Save username",
      onConfirm: async () => {
        setPending(true);
        setError(null);
        try {
          const result = await actions.set(body());
          const summary = usernameChangeSummary(result.accountUsernameChange);
          setNotice({ principalId: principal.principalId, source: "username", ...summary });
        } catch (failure) {
          setError(errorMessage(failure));
          throw failure;
        } finally {
          setPending(false);
        }
      }
    });
  }

  function confirmName() {
    const name = username.name!.accountUsername;
    confirm({
      title: `Confirm ${name}?`,
      body: `Confirm that ${who} is the person services already know as ${name}. Equal spelling is not proof.`,
      confirmLabel: "Confirm username",
      tone: "primary",
      onConfirm: async () => {
        await actions.confirm(name);
        // A confirmation is the latest save: an earlier change's report no longer describes the name.
        setNotice(null);
      }
    });
  }

  const fromEmailLine = savedMode === "from_email"
    ? fromEmailExplanation(username)
    : fromEmail ? `From email would give ${fromEmail}, from the saved email.` : usernameReasonText(username.fromEmail?.reason, username.email);
  return (
    <SettingsSection
      title="Username"
      description="The name services behind the gateway know this person by. Access keys can be issued and used only while it works."
      actions={<Badge tone={badge.tone}>{badge.label}</Badge>}
    >
      <UsernameChangeNotice notice={notice} principalId={principal.principalId} source="username" onDismiss={() => setNotice(null)} />
      {username.state === "awaiting_confirmation" && username.name ? (
        <Banner tone="warning" title="Awaiting confirmation" actions={writable ? <AdminButton onClick={confirmName}>Confirm</AdminButton> : undefined}>
          <span className="wb-mono">{username.name.accountUsername}</span> is on the operator’s list of usernames that services already use. It works for this account only after an administrator confirms that {who} is that person; equal spelling is not proof.
        </Banner>
      ) : null}
      {username.state === "conflict" && username.conflict ? (
        <Banner tone="danger" title="Username taken">
          <span className="wb-mono">{username.conflict.accountUsername}</span>, from this account’s email, already belongs to{" "}
          <AppLink className="wb-link" href={paths.principal(username.conflict.heldBy)}>{identityDisplayName(holder?.displayName) || username.conflict.heldBy}</AppLink>
          {holder?.email ? ` (${holder.email})` : ""}, who held it first and keeps it. This account has no username, so it cannot hold access keys. Choose Set by hand to give it another name.
        </Banner>
      ) : null}
      {username.state === "reserved" && username.name ? (
        <Banner tone="warning" title="Reserved name">
          <span className="wb-mono">{username.name.accountUsername}</span> is a name the operator reserved, so it does not work. Set another by hand.
        </Banner>
      ) : null}
      <SettingsRow label="Name" group alignTop help="Set from the email or by hand. A change of username ends this person’s access keys.">
        <div className="wb-form-stack pt-username-name">
          {writable ? (
            <Seg className="self-start" label="How the username is set" value={mode} onChange={(value) => { setMode(value); setError(null); }} options={[{ value: "from_email", label: "From email", disabled: pending }, { value: "manual", label: "Set by hand", disabled: pending }]} />
          ) : (
            <span>{savedMode === "manual" ? "Set by hand" : "From email"}</span>
          )}
          {mode === "from_email" ? (
            <div className="pt-username-value">
              <span className="wb-field-label">From email</span>
              <p className={held && savedMode === "from_email" ? "wb-mono" : "wb-muted"}>{savedMode === "from_email" ? held || "None" : fromEmail ?? "None"}</p>
              <p className="wb-field-hint">
                {fromEmailLine}{" "}
                {savedMode === "from_email"
                  ? "Changing the email may change this person’s username; if it does, their access keys end and their usage starts under the new username."
                  : "Switching to From email may change this person’s username; if it does, their access keys end and their usage starts under the new username."}
              </p>
            </div>
          ) : (
            <div className="pt-username-value">
              {writable ? <Input mono aria-label="Username set by hand" value={typed} onChange={(event) => setTyped(event.target.value)} disabled={pending} placeholder="No username" /> : <p className="wb-mono">{held || "None"}</p>}
              <p className="wb-field-hint">
                Stays until an administrator changes it. Changing it ends this person’s access keys.{" "}
                {fromEmail ? <>From email would give <span className="wb-mono">{fromEmail}</span>, from the saved email.</> : null}
                {!held && savedMode === "manual" && username.reason ? ` ${usernameReasonText(username.reason, username.email)}` : ""}
              </p>
            </div>
          )}
        </div>
      </SettingsRow>
      <SettingsRow label="History">
        <UsernameHistory username={username} />
      </SettingsRow>
      <FormError error={error} />
      <AdminOnly>
        <div className="wb-settings-actions">
          <AdminButton variant="primary" disabled={!dirty} pending={pending} onClick={save}>Save username</AdminButton>
        </div>
      </AdminOnly>
    </SettingsSection>
  );
}
