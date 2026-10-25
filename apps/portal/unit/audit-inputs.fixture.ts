// Synthetic stored audit records, one per action, shared by the unit tests and
// the mocked drawer spec. Each records only the inputs that action opts into;
// the first four also carry the outcome, identity and request fields of a
// realistic record.
import type { AuditRecord } from "../src/types";

/** A search string with a line break, markup, a control and a bidi override: shown as text, never as HTML. */
export const ADVERSARIAL_SEARCH = 'login timeout\n<script>alert("never")</script>\u0001\u202E' + "é".repeat(220);
/** A one-line issue title the broker cut to its 1 KiB bound. */
export const TRUNCATED_SUMMARY = "Checkout fails with a timeout when the payment provider responds slowly during peak traffic; ".repeat(12).slice(0, 1024);

function record(id: string, requestId: string, service: string, action: string, auditInputs?: unknown[], patch: Partial<AuditRecord> = {}): AuditRecord {
  return {
    auditId: id,
    nodeId: "fixture",
    timestamp: new Date().toISOString(),
    agentRequestId: `agent-${id}`,
    brokerRequestId: requestId,
    principal: "alice",
    service,
    action,
    decision: "allow",
    ...(auditInputs ? { auditInputs: auditInputs as AuditRecord["auditInputs"] } : {}),
    ...patch,
  };
}

const NODE = "broker-01.example.internal";
const TRUSTED_USER = { name: "trusted_user", type: "trusted_user", tokenClass: "agent_invoke", namespace: "managed_linux", readOnlyAccess: true };

/** An allowed read: a scope, a provider object ID, outcome details and a principal subject. */
export const CONFLUENCE_PAGE_VIEW = record("confluence-page-view", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a38", "confluence", "page.view", [
  { input: "pageId", label: "Page ID", value: "123456789" },
], {
  timestamp: "2026-10-25T18:36:20.518405+00:00",
  nodeId: NODE,
  principalSubject: "alice@example.test",
  groups: ["users"],
  resourceScopes: { confluence_space: ["DOCS"] },
  objectIds: { pageId: "123456789" },
  upstreamStatus: 200,
  upstreamDurationMs: 184,
  matchedGrant: { grantId: "docs-readers", subject: "group:users", priority: 100, grantVersion: 3 },
  credentialMode: "per_user",
  executionContext: "default",
  identitySource: TRUSTED_USER,
  configGeneration: 1,
  policyGeneration: 150,
});

export const JIRA_SEARCH = record("jira-search", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a31", "jira", "search", [
  { input: "query", label: "Query", value: { type: "jql", value: 'project = OPS AND status = "In Progress"' } },
  { input: "projects", label: "Projects", value: ["OPS"] },
], {
  timestamp: "2026-10-25T18:52:07.004913+00:00",
  nodeId: NODE,
  groups: ["users"],
  resourceScopes: { jira_project: ["OPS"] },
  upstreamStatus: 200,
  upstreamDurationMs: 412,
  matchedGrant: { grantId: "ops-readers", subject: "group:users", priority: 100 },
  credentialMode: "service",
  executionContext: "default",
  identitySource: { name: "managed-agents", type: "broker_tokens", tokenClass: "agent_invoke", tokenId: "4c1d8e2a-6b3f-4a5e-9d7c-1b2a3c4d5e6f" },
  configGeneration: 1,
  policyGeneration: 150,
});

/** A plain-text query: no language badge. */
export const JIRA_TEXT_SEARCH = record("jira-text-search", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a37", "jira", "search", [
  { input: "query", label: "Query", value: { type: "text", value: "checkout timeout" } },
  { input: "projects", label: "Projects", value: ["OPS", "SEC"] },
]);

/** Denied before any grant matched: the header says everything Outcome would. */
export const JIRA_ISSUE_CREATE = record("jira-issue-create", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a32", "jira", "issue.create", [
  { input: "project", label: "Project", value: "OPS" },
  { input: "summary", label: "Summary", value: TRUNCATED_SUMMARY, truncated: true },
], {
  timestamp: "2026-10-25T18:41:02.120044+00:00",
  nodeId: NODE,
  decision: "deny",
  reasonCode: "grant_not_found",
  groups: ["users", "ops-oncall"],
  resourceScopes: { jira_project: ["OPS"] },
  executionContext: "default",
  identitySource: TRUSTED_USER,
  configGeneration: 1,
  policyGeneration: 150,
});

/** Comment IDs beyond ±(2^53−1) arrive as decimal strings. */
export const JIRA_COMMENT_VIEW = record("jira-comment-view", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a33", "jira", "comment.view", [
  { input: "issue", label: "Issue", value: "OPS-42" },
  { input: "commentId", label: "Comment ID", value: "18446744073709551615" },
]);

export const GITLAB_ISSUE_SEARCH = record("gitlab-issue-search", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a34", "gitlab", "issue.search", [
  { input: "project", label: "Project", value: "platform/api" },
  { input: "search", label: "Search", value: ADVERSARIAL_SEARCH },
  { input: "state", label: "State", value: "opened" },
  { input: "milestone", label: "Milestone", value: null },
]);

/** GitLab's `iid` is a number, labeled by context; the last two entries are malformed and skipped. */
export const GITLAB_ISSUE_VIEW = record("gitlab-issue-view", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a35", "gitlab", "issue.view", [
  { input: "project", label: "Project", value: "platform/api" },
  { input: "iid", label: "Issue", value: 42 },
  "not-an-entry",
  { input: "dropped", label: "Dropped input" },
]);

/** A management change through a browser session by a principal the catalog does not name: no inputs. */
export const BROKER_GRANT_UPDATE = record("broker-grant-update", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a39", "broker", "admin.policy.grants.update", undefined, {
  timestamp: "2026-10-25T19:02:44.871230+00:00",
  nodeId: NODE,
  principal: "sam.lee",
  groups: ["admins"],
  providerAudit: { management: { operation: "admin.policy.grants.update", target: { grantId: "ops-readers" }, targetService: "jira", phase: "completed" } },
  identitySource: { name: "browser-session", type: "broker_tokens", tokenClass: "user_manage", tokenId: "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d" },
  configGeneration: 1,
  policyGeneration: 151,
});

/** An action that opts no inputs into audit. */
export const JIRA_PROJECT_LIST = record("jira-project-list", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a36", "jira", "project.list");

export const AUDIT_INPUT_RECORDS = [CONFLUENCE_PAGE_VIEW, JIRA_SEARCH, JIRA_TEXT_SEARCH, JIRA_ISSUE_CREATE, JIRA_COMMENT_VIEW, GITLAB_ISSUE_SEARCH, GITLAB_ISSUE_VIEW, BROKER_GRANT_UPDATE, JIRA_PROJECT_LIST];
