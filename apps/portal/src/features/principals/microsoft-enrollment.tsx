import { useState } from "react";
import { ApiError } from "../../api";
import type { MicrosoftEnrollment, PrincipalDetail } from "../../types";
import { useAdminLoginMethods, useAdminPrincipal, useConfigStatus, writeAuthorities } from "../../data/queries";
import { usePrincipalActions } from "../../mutations/principals";
import { errorMessage } from "../../lib/helpers";
import { AdminButton, AdminOnly } from "../../components/admin-access";
import { FormError } from "../../components/form";
import { Banner, Button, Field, Input, KeyValue, Modal, Time } from "../../workbench";

// Keep the record selected when the dialog opens: background reads must not
// replace the enrollment ID/revision that an administrator is reviewing.
type Draft = { action: "create"; enrollment: null } | { action: "edit" | "cancel"; enrollment: MicrosoftEnrollment };

export function MicrosoftEnrollmentControls({ principal }: { principal: PrincipalDetail }) {
  const config = useConfigStatus();
  const query = useAdminPrincipal(principal.principalId);
  const methods = useAdminLoginMethods(principal.principalId);
  const actions = usePrincipalActions();
  const enrollment = principal.microsoftEnrollment;
  const { groupWritesEnabled } = writeAuthorities(config.data);
  const available = groupWritesEnabled && Boolean(config.data?.microsoftEnrollment?.available);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [email, setEmail] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const title = draft?.action === "cancel" ? "Cancel Microsoft enrollment" : draft?.action === "edit" ? "Edit Microsoft enrollment" : "Prepare Microsoft sign-in";
  function open(next: Draft) {
    setDraft(next);
    setEmail(next.enrollment?.matchEmail ?? principal.email ?? "");
    setError(null);
    setConflict(false);
  }
  async function submit() {
    if (!draft || pending || conflict || !groupWritesEnabled || (draft.action !== "cancel" && (!available || !email.trim()))) return;
    setPending(true);
    setError(null);
    try {
      if (draft.action === "cancel") await actions.cancelMicrosoftEnrollment(draft.enrollment);
      else if (draft.action === "edit") await actions.editMicrosoftEnrollment(draft.enrollment, email);
      else await actions.createMicrosoftEnrollment(principal.principalId, email);
      setDraft(null);
    } catch (failure) {
      setError(errorMessage(failure));
      setConflict(failure instanceof ApiError && failure.status === 409);
    } finally {
      setPending(false);
    }
  }
  return <>
    {enrollment ? <>
      <KeyValue items={[
        { label: "Pending match email", value: enrollment.matchEmail },
        { label: "Tenant", value: <span className="wb-num">{enrollment.tenantId}</span> },
        { label: "Enrollment ID", value: <span className="wb-num">{enrollment.enrollmentId}</span> },
        { label: "Revision", value: enrollment.revision },
        { label: "Prepared", value: <><Time value={enrollment.createdAt} format="datetime" /> by {enrollment.createdBy}</> },
        { label: "Updated", value: <><Time value={enrollment.updatedAt} format="datetime" /> by {enrollment.updatedBy}</> }
      ]} />
      <p className="pt-prose">The first matching Microsoft sign-in uses this prepared account. Profile email changes do not change this reservation. Cancel enrollment before linking an Object ID.</p>
      {principal.status !== "active" ? <Banner tone="warning" slim>This account is disabled. Its email remains reserved, and Microsoft sign-in cannot bind it until the account is enabled.</Banner> : null}
      <AdminOnly><div className="flex flex-wrap gap-2">
        <AdminButton disabled={!available} onClick={() => open({ action: "edit", enrollment })}>Edit Microsoft enrollment</AdminButton>
        <AdminButton variant="danger-ghost" disabled={!groupWritesEnabled} onClick={() => open({ action: "cancel", enrollment })}>Cancel Microsoft enrollment</AdminButton>
      </div></AdminOnly>
    </> : <AdminOnly>
      <p className="pt-prose">Prepare a first Microsoft sign-in by email, or link a known Object ID below. Profile email alone does not enroll this account.</p>
      <div><AdminButton disabled={!available} onClick={() => open({ action: "create", enrollment: null })}>Prepare Microsoft sign-in</AdminButton></div>
    </AdminOnly>}
    {!available ? <p className="pt-prose">Creating or editing Microsoft enrollment requires managed identity and an available configured Microsoft tenant.</p> : null}
    {draft ? <Modal open title={title} onClose={() => setDraft(null)} dismissible={!pending} onSubmit={() => void submit()} footer={<>
      <Button disabled={pending} onClick={() => setDraft(null)}>Close</Button>
      {conflict ? <Button pending={pending} onClick={async () => {
        setPending(true);
        try {
          const results = await Promise.all([query.refetch(), methods.refetch()]);
          const failed = results.find((result) => result.isError);
          if (failed) { setError(errorMessage(failed.error)); return; }
          setDraft(null);
        } finally { setPending(false); }
      }}>Refresh enrollment</Button> : <AdminButton type="submit" variant={draft.action === "cancel" ? "danger" : "primary"} pending={pending} disabled={!groupWritesEnabled || (draft.action !== "cancel" && (!available || !email.trim()))}>{title}</AdminButton>}
    </>}>
      {draft.action === "cancel" ? <p className="pt-prose">Release the reservation for {draft.enrollment.matchEmail}? Prepared account settings, groups and grants remain. Cancellation does not prevent ordinary Microsoft account creation at sign-in.</p> : <div className="wb-form-stack">
        <p className="pt-prose">This authorizes the first matching Microsoft sign-in to use {principal.principalId}. No further approval is needed. A paused provider permits preparation; Microsoft sign-in requires it enabled.</p>
        <p className="pt-prose">Tenant: <span className="wb-num">{draft.enrollment?.tenantId ?? config.data?.microsoftEnrollment?.tenantId}</span></p>
        <Field label="Microsoft match email" hint="Independent of the profile email. Use the email returned by this tenant at Microsoft sign-in.">
          <Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required autoFocus disabled={pending || conflict} />
        </Field>
      </div>}
      <FormError error={error} />
      {conflict ? <p className="pt-prose">The enrollment could have changed or been consumed by sign-in. Refresh and review current state before trying again.</p> : null}
    </Modal> : null}
  </>;
}
