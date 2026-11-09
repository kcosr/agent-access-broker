import { issuanceSettingBlocker } from "../../lib/token-issuance-policy";
import { TokenIssuanceControls, useIssuanceRegistry } from "./token-issuance-controls";
import { AdminButton } from "../../components/admin-access";
import type { GroupAgentTokenIssuanceSetting, PrincipalAgentTokenIssuanceSetting, PrincipalRole } from "../../types";
import { ROLE_LABELS } from "../../lib/capabilities";
// Short create forms: user or service account, and group.
import { LOCAL_SIGN_IN_EXPLANATION, LOCAL_SIGN_IN_ACKNOWLEDGMENT } from "./sign-in-methods";
import { useState } from "react";
import { errorMessage, formatGroupOption } from "../../lib/helpers";
import { Banner, Button, Checkbox, Combobox, Field, Input, Modal, Select, Textarea } from "../../workbench";
import { FormError } from "../../components/form";
import { useAdminGroups, useConfigStatus, writeAuthorities } from "../../data/queries";
import { usePrincipalActions } from "../../mutations/principals";
import { useGroupActions } from "../../mutations/groups";
import { GroupEnrollmentCheckbox } from "./group-enrollment";

export function CreatePrincipalModal({ kind, onClose }: { kind: "user" | "service_account"; onClose: () => void }) {
  const serviceAccount = kind === "service_account";
  const title = serviceAccount ? "Create service account" : "Create user";
  const principals = usePrincipalActions();
  const groups = useAdminGroups().data ?? [];
  const config = useConfigStatus().data;
  const { groupWritesEnabled, identityAuthority } = writeAuthorities(config);
  const [principalId, setPrincipalId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [memberOf, setMemberOf] = useState<string[]>([]);
  const [role, setRole] = useState<PrincipalRole>("user");
  const [agentTokenIssuance, setAgentTokenIssuance] = useState<PrincipalAgentTokenIssuanceSetting>({ mode: "inherit", allowedExecutionContexts: [] });
  const [selfServiceEnabled, setSelfServiceEnabled] = useState(!serviceAccount);
  const [localAccount, setLocalAccount] = useState(false);
  const enrollMicrosoft = !serviceAccount && !localAccount;
  const microsoftAvailable = groupWritesEnabled && Boolean(config?.microsoftEnrollment?.available);
  const microsoftBlocked = enrollMicrosoft && (!microsoftAvailable || !email.trim());
  const [acknowledged, setAcknowledged] = useState(false);
  const registry = useIssuanceRegistry();
  const policyError = issuanceSettingBlocker(agentTokenIssuance, registry.contexts);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const blocked = Boolean(policyError) || microsoftBlocked || (!enrollMicrosoft && !principalId.trim()) || (localAccount && !acknowledged);

  async function submit() {
    if (blocked || pending) return;
    setPending(true);
    setError(null);
    try {
      await principals.create({
        ...(serviceAccount
          ? { kind: "service_account", principalId } as const
          : localAccount
            ? { kind: "user", signIn: "local", principalId } as const
            : { kind: "user", signIn: "microsoft" } as const),
        displayName, email, groups: groupWritesEnabled ? memberOf : [], role, selfServiceEnabled, agentTokenIssuance
      });
    } catch (failure) {
      setError(errorMessage(failure));
      void registry.query.refetch();
      setPending(false);
    }
  }

  return (
    <Modal
      open
      title={title}
      description={
        serviceAccount
          ? "Service accounts are noninteractive: no passwords, Microsoft login, browser sessions, setup tokens, or admin tokens."
          : localAccount
            ? "Create a user with a separate broker username and temporary password."
            : "Prepare access for a user before their first Microsoft sign-in. Creating the account approves their first matching sign-in."
      }
      onClose={onClose}
      dismissible={!pending}
      onSubmit={() => void submit()}
      footer={
        <>
          <Button onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <AdminButton type="submit" variant="primary" disabled={blocked} pending={pending}>
            {title}
          </AdminButton>
        </>
      }
    >
      <div className="wb-form-stack">
        {!serviceAccount ? <Checkbox
          label="Create a local account instead"
          checked={localAccount}
          onChange={(event) => { setLocalAccount(event.target.checked); setAcknowledged(false); setError(null); }}
        /> : null}
        {enrollMicrosoft ? <>
          {!microsoftAvailable ? <Banner tone="warning" slim>Microsoft account creation requires managed identity and a configured Microsoft tenant. You can explicitly choose a local account instead.</Banner> : null}
          <Field label="Microsoft email" hint="Use the email address on the user's Microsoft account.">
            <Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required autoFocus />
          </Field>
        </> : <Field label={serviceAccount ? "Principal ID" : "Username"} hint={serviceAccount ? "The stable identifier. It cannot be changed later." : "Used for local sign-in. It cannot be changed later."}>
          <Input mono value={principalId} onChange={(event) => setPrincipalId(event.target.value)} required autoFocus autoComplete="off" spellCheck={false} />
        </Field>}
        <Field label="Display name" optional hint={enrollMicrosoft ? "Microsoft sign-in refreshes this name from the Microsoft account." : undefined}>
          <Input value={displayName} onChange={(event) => setDisplayName(event.target.value)} />
        </Field>
        {!enrollMicrosoft ? <Field label="Email" optional>
          <Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} />
        </Field> : null}
        {enrollMicrosoft && microsoftAvailable ? <p className="pt-prose">Tenant: <span className="wb-num">{config?.microsoftEnrollment?.tenantId}</span>. A paused Microsoft provider permits preparation; sign-in requires it enabled. Automatic groups apply once at first Microsoft sign-in.</p> : null}
        <Field label="Groups" optional hint={groupWritesEnabled ? undefined : `Group changes are unavailable while identity authority is ${identityAuthority}.`}>
          <Combobox
            multiple
            value={memberOf}
            onChange={setMemberOf}
            disabled={!groupWritesEnabled}
            placeholder="Add a group…"
            options={groups.filter((group) => group.status === "active").map((group) => ({ value: group.groupId, label: formatGroupOption(group) }))}
          />
        </Field>
        {!serviceAccount && localAccount ? <>
          <p className="pt-prose">{LOCAL_SIGN_IN_EXPLANATION} A fresh temporary password will be shown once.</p>
          <Checkbox label={LOCAL_SIGN_IN_ACKNOWLEDGMENT} checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />
        </> : null}
        {!serviceAccount ? (
          <>
            <Field label="Role"><Select value={role} onChange={(event) => setRole(event.target.value as PrincipalRole)} options={Object.entries(ROLE_LABELS).map(([value, label]) => ({ value, label }))} /></Field>
            <Field label="Agent token issuance"><TokenIssuanceControls value={agentTokenIssuance} onChange={setAgentTokenIssuance} registry={registry} /></Field>
            <Checkbox label="Self-service enabled" description="Manage personal tokens, credentials, connections and activity." checked={selfServiceEnabled} onChange={(event) => setSelfServiceEnabled(event.target.checked)} />
          </>
        ) : null}
        {serviceAccount ? <p className="pt-prose">Self-issuance is unavailable for service accounts. Administrators can issue their agent tokens.</p> : null}
        <FormError error={error} />
      </div>
    </Modal>
  );
}

export function CreateGroupModal({ onClose }: { onClose: () => void }) {
  const groups = useGroupActions();
  const { groupWritesEnabled, identityAuthority } = writeAuthorities(useConfigStatus().data);
  const [groupId, setGroupId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const [agentTokenIssuance, setAgentTokenIssuance] = useState<GroupAgentTokenIssuanceSetting>({ mode: "disabled", allowedExecutionContexts: [] });
  const [autoEnrollNewMicrosoftUsers, setAutoEnrollNewMicrosoftUsers] = useState(false);
  const registry = useIssuanceRegistry();
  const policyError = issuanceSettingBlocker(agentTokenIssuance, registry.contexts);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal
      open
      title="Create group"
      onClose={onClose}
      dismissible={!pending}
      onSubmit={async () => {
        if (!groupId.trim() || policyError) return;
        setPending(true);
        setError(null);
        try {
          await groups.create({ groupId, displayName, description, autoEnrollNewMicrosoftUsers, agentTokenIssuance });
        } catch (failure) {
          setError(errorMessage(failure));
          void registry.query.refetch();
          setPending(false);
        }
      }}
      footer={
        <>
          <Button onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <AdminButton type="submit" variant="primary" disabled={!groupId.trim() || !groupWritesEnabled || Boolean(policyError)} pending={pending}>
            Create group
          </AdminButton>
        </>
      }
    >
      <div className="wb-form-stack">
        {!groupWritesEnabled ? (
          <Banner tone="warning" slim>
            Group writes are unavailable while identity authority is {identityAuthority}.
          </Banner>
        ) : null}
        <Field label="Group ID">
          <Input mono value={groupId} onChange={(event) => setGroupId(event.target.value)} required autoFocus autoComplete="off" spellCheck={false} />
        </Field>
        <Field label="Display name" optional>
          <Input value={displayName} onChange={(event) => setDisplayName(event.target.value)} />
        </Field>
        <Field label="Description" optional>
          <Textarea value={description} onChange={(event) => setDescription(event.target.value)} rows={3} />
        </Field>
        {groupWritesEnabled ? <Field label="Agent token issuance" hint="Disabled does not override another group’s permission. An explicit account setting wins."><TokenIssuanceControls group value={agentTokenIssuance} onChange={(value) => setAgentTokenIssuance(value as GroupAgentTokenIssuanceSetting)} registry={registry} /></Field> : <p className="pt-prose">Group token issuance is unavailable under {identityAuthority} identity authority.</p>}
        <GroupEnrollmentCheckbox checked={autoEnrollNewMicrosoftUsers} onChange={(event) => setAutoEnrollNewMicrosoftUsers(event.target.checked)} disabled={!groupWritesEnabled} />
        <FormError error={error} />
      </div>
    </Modal>
  );
}
