// App-level UI types: grant drafts and the app-wide modal slot.
import type { ReactNode } from "react";
import type { AgentTokenOptions, BrokerTokenRecord, PolicyValidationMessage, ResourceSelection, TokenTtlPolicy } from "./types";
import type { Tone } from "./workbench";

export type BadgeTone = Tone;
export type PolicySubjectKind = "group" | "user" | "anonymousUser" | "anonymousGroup";
export type PolicyGrantDraft = {
  mode: "create" | "edit" | "duplicate" | "inspect";
  grantRef?: string;
  originalService?: string;
  originalCredentialMode?: string;
  originalActions?: string[];
  writable: boolean;
  version?: number | null;
  grantId: string;
  subjects: string[];
  subjectKind: PolicySubjectKind;
  subjectId: string;
  service: string;
  actions: string[];
  executionContexts: string[];
  credentialMode: string;
  status: string;
  priority: string;
  description: string;
  resources: ResourceSelection;
  validationMessages: PolicyValidationMessage[];
};

export type AgentTokenModal = {
  type: "token";
  administrative: boolean;
  targetPrincipalId: string;
  options: AgentTokenOptions;
  accessMode: "policy" | "restricted";
  screen: "edit" | "access" | "review";
  selectedExecutionContexts: string[];
  selectedServices: string[];
  selectedActions: Record<string, string[]>;
  resourceSelections: Record<string, ResourceSelection | undefined>;
  name: string;
  lifetime: string;
  ttlPolicy: TokenTtlPolicy;
};

export type ConfirmModal = {
  type: "confirm";
  title: string;
  body: ReactNode;
  confirmLabel: string;
  /** danger (default) or primary for non-destructive confirmations. */
  tone?: "danger" | "primary";
  /** Rejections keep the dialog open and show the message. */
  onConfirm: () => Promise<unknown>;
};

export type ModalState =
  | AgentTokenModal
  | { type: "managementToken"; principalId: string; tokenClass: "user_manage" | "admin"; ttlPolicy: TokenTtlPolicy }
  | { type: "createPrincipal"; kind: "user" | "service_account" }
  | { type: "createGroup" }
  | { type: "assignManager"; service?: string }
  | { type: "passwordReveal"; principalId: string; password: string; action: "created" | "reset" | "enabled"; afterClose?: () => void }
  | { type: "reveal"; token: string; record: BrokerTokenRecord; principalId?: string; options?: AgentTokenOptions }
  | ConfirmModal
  | null;
