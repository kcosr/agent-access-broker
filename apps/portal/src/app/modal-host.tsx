// Renders the open app-wide modal with the data and mutations it needs.
import { useEffect } from "react";
import type { ModalState } from "../app-types";
import { reconcileAgentTokenModalOptions, tokenExecutionContextsSummary } from "../lib/helpers";
import { ConfirmDialog, KeyValue, Time } from "../workbench";
import { SecretRevealModal } from "../components/secret-reveal";
import { useAgentTokenOptions } from "../data/queries";
import { useAgentTokenActions, useManagementTokenActions } from "../mutations/tokens";
import { IssueTokenModal } from "../features/tokens/issue-token-modal";
import { ManagementTokenModal } from "../features/tokens/management-token-modal";
import { TokenBoundary } from "../features/tokens/token-boundary";
import { CreateGroupModal, CreatePrincipalModal } from "../features/principals/create-modals";
import { AssignManagerModal } from "../features/policies/assign-manager-modal";
import { adminSubject, useSelfSubject } from "./active-route";
import { useModal } from "./modal";

export function ModalHost() {
  const { modal } = useModal();
  return modal ? <OpenModal modal={modal} /> : null;
}

function OpenModal({ modal }: { modal: Exclude<ModalState, null> }) {
  const { closeModal, setModal } = useModal();
  switch (modal.type) {
    case "token":
      return <AgentTokenIssue modal={modal} />;
    case "managementToken":
      return <ManagementTokenIssue modal={modal} />;
    case "createPrincipal":
      return <CreatePrincipalModal kind={modal.kind} onClose={closeModal} />;
    case "createGroup":
      return <CreateGroupModal onClose={closeModal} />;
    case "assignManager":
      return <AssignManagerModal service={modal.service} onClose={closeModal} />;
    case "passwordReveal":
      return (
        <SecretRevealModal
          title={modal.action === "created" ? "User created" : modal.action === "enabled" ? "Local password sign-in enabled" : "Local password reset"}
          secretLabel="Temporary password"
          secret={modal.password}
          onClose={() => { closeModal(); modal.afterClose?.(); }}
          details={
            <KeyValue
              items={[
                { label: "Principal", value: <span className="wb-num">{modal.principalId}</span> },
                { label: "Next local sign-in", value: "Must change this password" }
              ]}
            />
          }
        />
      );
    case "reveal":
      return (
        <SecretRevealModal
          title="Token created"
          secretLabel="Token"
          secret={modal.token}
          onClose={closeModal}
          details={
            <>
              <KeyValue
                items={[
                  { label: "Owner", value: <span className="wb-num">{modal.principalId ?? modal.record.principalId}</span> },
                  { label: "Token class", value: <span className="wb-num">{modal.record.tokenClass}</span> },
                  { label: "Token ID", value: <span className="wb-num">{modal.record.tokenId}</span> },
                  { label: "Expires", value: modal.record.expiresAt ? <Time value={modal.record.expiresAt} format="datetime" /> : "Never" },
                  modal.record.tokenClass === "agent_invoke"
                    ? { label: "Contexts", value: <span className="wb-mono">{tokenExecutionContextsSummary(modal.record, modal.options?.executionContexts)}</span> }
                    : null
                ]}
              />
              {modal.record.tokenClass === "agent_invoke" ? (
                modal.record.scopes.serviceRestrictions ? (
                  <TokenBoundary record={modal.record} options={modal.options} contexts={false} />
                ) : (
                  <p className="pt-prose">All actions and resources allowed by current grants.</p>
                )
              ) : null}
            </>
          }
        />
      );
    case "confirm":
      return (
        // Close only this confirmation: its action may already have opened the next dialog (a one-time secret).
        <ConfirmDialog
          open
          onClose={() => setModal((current) => (current === modal ? null : current))}
          title={modal.title}
          confirmLabel={modal.confirmLabel}
          tone={modal.tone}
          onConfirm={modal.onConfirm}
        >
          <p>{modal.body}</p>
        </ConfirmDialog>
      );
  }
}

function AgentTokenIssue({ modal }: { modal: Extract<ModalState, { type: "token" }> }) {
  const { setModal } = useModal();
  const self = useSelfSubject();
  const subject = modal.administrative ? adminSubject(modal.targetPrincipalId) : self;
  const { options } = useAgentTokenOptions(subject);
  const actions = useAgentTokenActions(subject, options);
  // Keep the open dialog in step with refreshed options for the same owner.
  useEffect(() => {
    if (!options) return;
    setModal((current) => (current?.type === "token" && current.options !== options ? reconcileAgentTokenModalOptions(current, options) : current));
  }, [options, setModal]);
  return <IssueTokenModal modal={modal} setModal={setModal} onIssue={actions.issue} />;
}

function ManagementTokenIssue({ modal }: { modal: Extract<ModalState, { type: "managementToken" }> }) {
  const { closeModal } = useModal();
  const actions = useManagementTokenActions();
  return (
    <ManagementTokenModal
      principalId={modal.principalId}
      tokenClass={modal.tokenClass}
      ttlPolicy={modal.ttlPolicy}
      onClose={closeModal}
      onIssue={(name, lifetime) => actions.issue(modal.principalId, modal.tokenClass, name, lifetime)}
    />
  );
}
