import { AdminForm, AdminButton } from "../../components/admin-access";
import { canWriteAdmin, ROLE_LABELS } from "../../lib/capabilities";
import { AdminOnly } from "../../components/admin-access";
import { useConfigStatus, usePolicyCatalog, useServicePolicyManagers } from "../../data/queries";
import { usePolicyActions } from "../../mutations/policy";
import { useModal } from "../../app/modal";
import type { PrincipalRole } from "../../types";
// User page › Overview: profile, status and role, sign-in methods, identity token.
import { LOCAL_SIGN_IN_EXPLANATION, LOCAL_SIGN_IN_ACKNOWLEDGMENT } from "./sign-in-methods";
import { useEffect, useState } from "react";
import type { LoginMethodRecord, PrincipalDetail } from "../../types";
import { errorMessage, microsoftLoginControl } from "../../lib/helpers";
import {
  Badge,
  Button,
  Checkbox,
  ErrorState,
  IconButton,
  Input,
  Modal,
  Select,
  KeyValue,
  SettingsPage,
  SettingsRow,
  SettingsSection,
  SkeletonBlock,
  Time,
  useToast
} from "../../workbench";
import { FormError } from "../../components/form";
import { useActionRunner } from "../../app/actions";
import { useSession } from "../../app/session";
import { usePrincipalActions } from "../../mutations/principals";
import { IdentityTokenSection } from "./identity-token";
import { IdentityAccessSection } from "./identity-access";

export function PrincipalOverview({
  principal,
  loginMethods,
  groupWritesEnabled
}: {
  principal: PrincipalDetail;
  loginMethods: LoginMethodRecord[];
  groupWritesEnabled: boolean;
}) {
  const serviceAccount = principal.kind === "service_account";
  return (
    <SettingsPage>
      <ProfileSection principal={principal} />
      {serviceAccount ? (
        <SettingsSection title="Sign-in" description="Service accounts are noninteractive.">
          <p className="pt-prose">
            Service accounts cannot use passwords, Microsoft sign-in, browser sessions, setup tokens, or admin tokens. Administrators assign grants,
            credentials, groups, and agent-token boundaries on the other tabs.
          </p>
        </SettingsSection>
      ) : (
        <>
          <RoleSection key={principal.principalId} principal={principal} />
          {principal.role === "service_policy_manager" ? <ManagedServicesSection principal={principal} /> : null}
          <SignInSection principal={principal} loginMethods={loginMethods} groupWritesEnabled={groupWritesEnabled} />
          {principal.kind === "user" ? (
            <>
              <IdentityAccessSection key={`access:${principal.principalId}`} principalId={principal.principalId} principalActive={principal.status === "active"} />
              {/* Keyed: a revealed token, typed replacement, or pending reveal never carries over to another principal. */}
              <IdentityTokenSection key={principal.principalId} principalId={principal.principalId} />
            </>
          ) : null}
        </>
      )}
    </SettingsPage>
  );
}

function ProfileSection({ principal }: { principal: PrincipalDetail }) {
  const principals = usePrincipalActions();
  const [displayName, setDisplayName] = useState(principal.displayName ?? "");
  const [email, setEmail] = useState(principal.email ?? "");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setDisplayName(principal.displayName ?? "");
    setEmail(principal.email ?? "");
  }, [principal.principalId, principal.displayName, principal.email]);
  const dirty = displayName !== (principal.displayName ?? "") || email !== (principal.email ?? "");
  return (
    <SettingsSection title="Profile">
      <AdminForm
        onSubmit={async (event) => {
          event.preventDefault();
          setPending(true);
          setError(null);
          try {
            await principals.patch(principal.principalId, { displayName: displayName || null, email: email || null });
          } catch (failure) {
            setError(errorMessage(failure));
          } finally {
            setPending(false);
          }
        }}
      >
        <SettingsRow label="Principal ID" help="The stable identifier; it cannot change.">
          <span className="wb-num">{principal.principalId}</span>
        </SettingsRow>
        <SettingsRow label="Display name">
          <Input value={displayName} onChange={(event) => setDisplayName(event.target.value)} className="flex-1" />
        </SettingsRow>
        <SettingsRow label="Email">
          <Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} className="flex-1" />
        </SettingsRow>
        <SettingsRow label="History">
          <KeyValue
            items={[
              { label: "Created", value: <><Time value={principal.createdAt} format="datetime" /> <span className="wb-muted">by {principal.createdBy}</span></> },
              { label: "Updated", value: <Time value={principal.updatedAt} format="datetime" /> }
            ]}
          />
        </SettingsRow>
        <FormError error={error} />
        <div className="wb-settings-actions">
          <AdminButton type="submit" variant="primary" disabled={!dirty} pending={pending}>
            Save profile
          </AdminButton>
        </div>
      </AdminForm>
    </SettingsSection>
  );
}

function RoleSection({ principal }: { principal: PrincipalDetail }) {
  const principals = usePrincipalActions();
  const { session } = useSession();
  const { confirm } = useModal();
  const configQuery = useConfigStatus();
  const assignmentsAvailable = configQuery.data?.identityAuthority === "managed" && configQuery.data.policyAuthority === "managed";
  const assignmentsQuery = useServicePolicyManagers(assignmentsAvailable && principal.role === "service_policy_manager");
  const assignments = assignmentsQuery.data ?? [];
  const [role, setRole] = useState(principal.role);
  const [selfServiceEnabled, setSelfServiceEnabled] = useState(principal.selfServiceEnabled);
  useEffect(() => { setRole(principal.role); setSelfServiceEnabled(principal.selfServiceEnabled); }, [principal.role, principal.selfServiceEnabled]);
  const self = principal.principalId === session.principal;
  const writable = canWriteAdmin(session);
  const roles = Object.entries(ROLE_LABELS).filter(([value]) => principal.kind !== "system" || value === "user" || value === "service_policy_manager");
  const scopes = assignments.filter((assignment) => assignment.principalId === principal.principalId).map((assignment) => assignment.service);
  const changedRole = role !== principal.role;
  const leavingManager = changedRole && principal.role === "service_policy_manager";
  const scopePreviewReady = configQuery.isSuccess && (!assignmentsAvailable || assignmentsQuery.isSuccess);
  const scopeWarning = !leavingManager ? "" : assignmentsAvailable
    ? ` Direct management assignments will be removed: ${scopes.join(", ") || "none"}.`
    : " Any stored direct management assignments will be removed. Assignment names are unavailable while policy is file-owned.";
  const save = () => confirm({
    title: "Update account access?",
    body: `${principal.principalId} will have the ${ROLE_LABELS[role]} role and self-service ${selfServiceEnabled ? "enabled" : "disabled"}.${changedRole ? " All administrative API tokens for this account will be revoked." : ""}${scopeWarning}`,
    confirmLabel: "Update access", tone: "primary",
    onConfirm: () => principals.setAccess(principal.principalId, { role, selfServiceEnabled })
  });
  return (
    <SettingsSection title="Account access" description="One administrative role, with independent access to personal tokens, credentials and connections.">
      <SettingsRow label="Role" help={self ? "You cannot change your own role here." : undefined}>
        {writable ? <Select aria-label="Role" value={role} disabled={self} onChange={(event) => setRole(event.target.value as PrincipalRole)} options={roles.map(([value, label]) => ({ value, label }))} /> : <span>{ROLE_LABELS[principal.role]}</span>}
      </SettingsRow>
      <SettingsRow label="Self-service">
        {writable ? <Checkbox label="Self-service enabled" checked={selfServiceEnabled} onChange={(event) => setSelfServiceEnabled(event.target.checked)} /> : <span>{principal.selfServiceEnabled ? "Enabled" : "Disabled"}</span>}
      </SettingsRow>
      {leavingManager && configQuery.isError ? <ErrorState error={configQuery.error} onRetry={() => void configQuery.refetch()} retrying={configQuery.isFetching} /> : null}
      {leavingManager && assignmentsAvailable && assignmentsQuery.isError ? <ErrorState error={assignmentsQuery.error} onRetry={() => void assignmentsQuery.refetch()} retrying={assignmentsQuery.isFetching} /> : null}
      <AdminOnly><div className="wb-settings-actions"><AdminButton disabled={(!changedRole && selfServiceEnabled === principal.selfServiceEnabled) || (leavingManager && !scopePreviewReady)} onClick={save}>Save access</AdminButton></div></AdminOnly>
    </SettingsSection>
  );
}

function ManagedServicesSection({ principal }: { principal: PrincipalDetail }) {
  const { session } = useSession();
  const config = useConfigStatus();
  const assignmentsAvailable = config.data?.identityAuthority === "managed" && config.data.policyAuthority === "managed";
  const catalog = usePolicyCatalog(assignmentsAvailable);
  const assignments = useServicePolicyManagers(assignmentsAvailable);
  const policy = usePolicyActions();
  const current = (assignments.data ?? []).filter((item) => item.principalId === principal.principalId).map((item) => item.service).sort();
  const key = JSON.stringify(current);
  const [selected, setSelected] = useState<string[]>(current);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  useEffect(() => { setSelected(JSON.parse(key) as string[]); }, [key]);
  const services = [...new Set([...(catalog.data?.services ?? []).map((item) => item.service), ...current])].sort();
  const writable = canWriteAdmin(session);
  if (!config.isSuccess || !assignmentsAvailable) return <SettingsSection title="Managed services">
    {config.isError ? <ErrorState error={config.error} onRetry={() => void config.refetch()} retrying={config.isFetching} /> : config.isPending ? <SkeletonBlock lines={2} /> : <p className="pt-prose">Service management assignments are available only when identity and policy are managed.</p>}
  </SettingsSection>;
  if (!catalog.isSuccess || !assignments.isSuccess) return <SettingsSection title="Managed services">
    {assignments.isError ? <ErrorState error={assignments.error} onRetry={() => void assignments.refetch()} retrying={assignments.isFetching} /> : catalog.isError ? <ErrorState error={catalog.error} onRetry={() => void catalog.refetch()} retrying={catalog.isFetching} /> : <SkeletonBlock lines={2} />}
  </SettingsSection>;
  return <SettingsSection title="Managed services" description="This account can manage every grant for the selected services. Group membership does not grant management authority.">
    {services.map((service) => <Checkbox key={service} label={catalog.data?.services.find((item) => item.service === service)?.displayName ?? service} checked={selected.includes(service)} disabled={!writable || pending} onChange={(event) => setSelected((values) => event.target.checked ? [...values, service] : values.filter((value) => value !== service))} />)}
    {!current.length ? <p className="pt-prose">No services assigned.</p> : null}
    <FormError error={error} />
    <AdminOnly><AdminButton disabled={assignments.isPending || catalog.isPending || JSON.stringify([...selected].sort()) === key} pending={pending} onClick={async () => {
      setPending(true); setError(null);
      try {
        for (const service of selected.filter((value) => !current.includes(value))) await policy.assignManager(service, principal.principalId);
        for (const service of current.filter((value) => !selected.includes(value))) await policy.revokeManager(service, principal.principalId);
      } catch (failure) { setError(errorMessage(failure)); } finally { setPending(false); }
    }}>Save managed services</AdminButton></AdminOnly>
  </SettingsSection>;
}

function SignInSection({ principal, loginMethods, groupWritesEnabled }: { principal: PrincipalDetail; loginMethods: LoginMethodRecord[]; groupWritesEnabled: boolean }) {
  const { session } = useSession();
  const principals = usePrincipalActions();
  const runner = useActionRunner();
  const toast = useToast();
  const localPassword = loginMethods.find((method) => method.method === "local_password");
  const microsoft = loginMethods.find((method) => method.method === "oidc" && method.oidc?.provider === "microsoft");
  const control = microsoftLoginControl(microsoft?.status, Boolean(session.loginOptions?.microsoft?.enabled));
  const [objectId, setObjectId] = useState("");
  const [confirmId, setConfirmId] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [linkError, setLinkError] = useState<string | null>(null);
  const [linking, setLinking] = useState(false);
  const [enableOpen, setEnableOpen] = useState(false);
  const [enableAcknowledged, setEnableAcknowledged] = useState(false);
  const [enablePending, setEnablePending] = useState(false);
  const [enableError, setEnableError] = useState<string | null>(null);
  const localActive = localPassword?.status === "active";
  const enableLabel = localPassword ? "Re-enable local password sign-in" : "Enable local password sign-in";
  useEffect(() => {
    setObjectId("");
    setConfirmId("");
    setAcknowledged(false);
  }, [principal.principalId]);
  const canLink = groupWritesEnabled && objectId.trim() && confirmId === principal.principalId && acknowledged;
  return (
    <SettingsSection title="Sign-in methods" description="Enrollment is separate from user status and broker-wide sign-in availability.">
      {session.loginOptions?.localPassword?.enabled === false ? <p className="pt-prose">Local password sign-in is disabled for this broker. Enrolled methods are retained.</p> : null}
      {enableOpen ? (
        <Modal
          open
          title={enableLabel}
          onClose={() => setEnableOpen(false)}
          dismissible={!enablePending}
          onSubmit={async () => {
            if (!enableAcknowledged || enablePending) return;
            setEnablePending(true);
            setEnableError(null);
            try {
              await principals.enablePassword(principal.principalId);
              setEnableOpen(false);
            } catch (error) {
              setEnableError(errorMessage(error));
            } finally {
              setEnablePending(false);
            }
          }}
          footer={
            <>
              <Button disabled={enablePending} onClick={() => setEnableOpen(false)}>Cancel</Button>
              <AdminButton type="submit" variant="primary" disabled={!enableAcknowledged} pending={enablePending}>{enableLabel}</AdminButton>
            </>
          }
        >
          <p className="pt-prose">{LOCAL_SIGN_IN_EXPLANATION} A fresh temporary password is generated and must be changed at first local sign-in.</p>
          <Checkbox label={LOCAL_SIGN_IN_ACKNOWLEDGMENT} checked={enableAcknowledged} onChange={(event) => setEnableAcknowledged(event.target.checked)} disabled={enablePending} />
          <FormError error={enableError} />
        </Modal>
      ) : null}
      <SettingsRow
        label="Local password"
        help={
          localPassword?.mustChangePassword ? (
            "Must change it at next sign-in."
          ) : localPassword?.passwordSetAt ? (
            <>
              Set <Time value={localPassword.passwordSetAt} />
            </>
          ) : localPassword ? undefined : (
            "No local password sign-in is configured."
          )
        }
      >
        <Badge tone={localPassword?.status === "active" ? "success" : "neutral"}>{localPassword ? localPassword.status : "not configured"}</Badge>
        {localPassword?.locked && localPassword.lockedUntil ? (
          <span className="wb-small">
            Some sources locked until <Time value={localPassword.lockedUntil} format="datetime" />
          </span>
        ) : null}
        <span className="wb-spacer" />
        {localActive ? <>
          <AdminButton icon="key" onClick={() => principals.confirmResetPassword(principal.principalId)}>Reset local password</AdminButton>
          {localPassword?.locked ? <AdminButton pending={runner.isPending("unlock")} onClick={() => void runner.run("unlock", () => principals.updateLoginMethod(principal.principalId, "unlock"))}>Unlock local password</AdminButton> : null}
          <AdminButton variant="danger-ghost" onClick={() => principals.confirmDisablePassword(principal.principalId)}>Disable local password sign-in</AdminButton>
        </> : <AdminButton icon="key" onClick={() => { setEnableAcknowledged(false); setEnableError(null); setEnableOpen(true); }}>{enableLabel}</AdminButton>}

      </SettingsRow>
      <SettingsRow label="Microsoft" alignTop help={control === "disabled" ? "Microsoft sign-in is not enabled for this broker." : session.loginOptions?.microsoft?.available === false ? "Microsoft sign-in is temporarily unavailable. Enrolled methods are retained." : undefined}>
        <div className="flex flex-1 flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={microsoft?.status === "active" ? "success" : "neutral"}>{microsoft?.status ?? "not linked"}</Badge>
            {microsoft?.oidc ? (
              <>
                <span className="wb-small">
                  tenant <span className="wb-num">{microsoft.oidc.tenantId}</span>
                </span>
                <span className="wb-small">
                  object <span className="wb-num">{microsoft.oidc.userObjectId}</span>
                </span>
                <IconButton
                  size="sm"
                  icon="copy"
                  label="Copy Microsoft user Object ID"
                  onClick={() => void navigator.clipboard.writeText(microsoft.oidc!.userObjectId).then(() => toast("Object ID copied"))}
                />
              </>
            ) : null}
            {control === "unlink" ? (
              <>
                <span className="wb-spacer" />
                <AdminButton variant="danger-ghost" disabled={!groupWritesEnabled} onClick={() => principals.confirmUnlinkMicrosoft(principal.principalId)}>
                  Unlink Microsoft login
                </AdminButton>
              </>
            ) : null}
          </div>
          {control === "link" ? (
            <AdminForm
              className="wb-form-stack"
              onSubmit={async (event) => {
                event.preventDefault();
                if (!canLink) return;
                setLinking(true);
                setLinkError(null);
                try {
                  await principals.linkMicrosoft(principal.principalId, objectId.trim());
                  setObjectId("");
                  setConfirmId("");
                  setAcknowledged(false);
                } catch (failure) {
                  setLinkError(errorMessage(failure));
                } finally {
                  setLinking(false);
                }
              }}
            >
              {localActive ? <p className="pt-prose">Linking Microsoft keeps this user’s independent local password sign-in enabled.</p> : null}
              <div className="pt-form-row">
                <Input mono aria-label="Microsoft User Object ID" placeholder="00000000-0000-0000-0000-000000000000" value={objectId} onChange={(event) => setObjectId(event.target.value)} disabled={!groupWritesEnabled} />
                <Input mono aria-label="Confirm Principal ID" placeholder={principal.principalId} value={confirmId} onChange={(event) => setConfirmId(event.target.value)} disabled={!groupWritesEnabled} />
              </div>
              <Checkbox
                label={<>I understand this Microsoft account will be able to authenticate as {principal.principalId}.</>}
                checked={acknowledged}
                onChange={(event) => setAcknowledged(event.target.checked)}
                disabled={!groupWritesEnabled}
              />
              <FormError error={linkError} />
              <div>
                <AdminButton type="submit" disabled={!canLink} pending={linking}>
                  Link Microsoft login
                </AdminButton>
              </div>
            </AdminForm>
          ) : null}
        </div>
      </SettingsRow>
    </SettingsSection>
  );
}
