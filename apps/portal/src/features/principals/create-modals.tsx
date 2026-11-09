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
  const [enrollMicrosoft, setEnrollMicrosoft] = useState(false);
  const microsoftAvailable = groupWritesEnabled && Boolean(config?.microsoftEnrollment?.available);
  const microsoftBlocked = enrollMicrosoft && (!microsoftAvailable || !email.trim());
  const [enableLocalPassword, setEnableLocalPassword] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const registry = useIssuanceRegistry();
  const policyError = issuanceSettingBlocker(agentTokenIssuance, registry.contexts);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    if (!principalId.trim() || policyError || microsoftBlocked || (enableLocalPassword && !acknowledged)) return;
    setPending(true);
    setError(null);
    try {
      await principals.create({ kind, principalId, displayName, email, groups: groupWritesEnabled ? memberOf : [], role, selfServiceEnabled, agentTokenIssuance, enableLocalPassword, enrollMicrosoft });
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
          : "Prepare a user and their access before first sign-in. Choose Microsoft email enrollment to authorize their first matching Microsoft sign-in. Local password sign-in is optional."
      }
      onClose={onClose}
      dismissible={!pending}
      onSubmit={() => void submit()}
      footer={
        <>
          <Button onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <AdminButton type="submit" variant="primary" disabled={!principalId.trim() || Boolean(policyError) || microsoftBlocked || (enableLocalPassword && !acknowledged)} pending={pending}>
            {title}
          </AdminButton>
        </>
      }
    >
      <div className="wb-form-stack">
        <Field label="Principal ID" hint="The stable identifier, for example an email address. It cannot be changed later.">
          <Input mono value={principalId} onChange={(event) => setPrincipalId(event.target.value)} required autoFocus autoComplete="off" spellCheck={false} />
        </Field>
        <Field label="Display name" optional hint={!serviceAccount ? "Microsoft sign-in refreshes this name from the Microsoft account." : undefined}>
          <Input value={displayName} onChange={(event) => setDisplayName(event.target.value)} />
        </Field>
        {!serviceAccount ? <Checkbox
          label="Prepare Microsoft sign-in by email"
          description={microsoftAvailable ? "The first validated Microsoft sign-in with this email joins this prepared account. Creating the account approves that sign-in; no later approval is needed." : "Microsoft enrollment requires managed identity and a configured Microsoft tenant."}
          checked={enrollMicrosoft}
          onChange={(event) => setEnrollMicrosoft(event.target.checked)}
          disabled={!microsoftAvailable && !enrollMicrosoft}
        /> : null}
        <Field label={enrollMicrosoft ? "Microsoft email" : "Email"} optional={!enrollMicrosoft} hint={enrollMicrosoft ? "Saved as profile email and pending match email initially. You can edit them separately after creation." : "Profile email alone does not authorize Microsoft enrollment."}>
          <Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required={enrollMicrosoft} />
        </Field>
        {enrollMicrosoft ? <p className="pt-prose">Tenant: <span className="wb-num">{config?.microsoftEnrollment?.tenantId}</span>. A paused Microsoft provider permits preparation; sign-in requires it enabled. Initial automatic local groups apply once at the first successful Microsoft sign-in.</p> : null}
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
        {!serviceAccount ? <>
          <Checkbox label="Enable local password sign-in" checked={enableLocalPassword} onChange={(event) => { setEnableLocalPassword(event.target.checked); setAcknowledged(false); }} />
          {enableLocalPassword ? <>
            <p className="pt-prose">{LOCAL_SIGN_IN_EXPLANATION} A fresh temporary password will be shown once.</p>
            <Checkbox label={LOCAL_SIGN_IN_ACKNOWLEDGMENT} checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />
          </> : null}
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
