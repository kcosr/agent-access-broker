// Synthetic stored audit records, one per action, shared by the unit tests and
// the mocked drawer spec. Each records only the inputs that action opts into.
import type { AuditRecord } from "../src/types";

/** A search string with a line break, markup, a control and a bidi override: shown as text, never as HTML. */
export const ADVERSARIAL_SEARCH = 'login timeout\n<script>alert("never")</script>\u0001\u202E' + "é".repeat(220);
/** A one-line issue title the broker cut to its 1 KiB bound. */
export const TRUNCATED_SUMMARY = "Checkout fails with a timeout when the payment provider responds slowly during peak traffic; ".repeat(12).slice(0, 1024);

function record(id: string, requestId: string, service: string, action: string, auditInputs?: unknown[]): AuditRecord {
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
  };
}

export const JIRA_SEARCH = record("jira-search", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a31", "jira", "search", [
  { input: "query", label: "Query", value: { type: "jql", value: 'project = OPS AND status = "In Progress"' } },
  { input: "projects", label: "Projects", value: ["OPS"] },
]);

/** A plain-text query: no language badge. */
export const JIRA_TEXT_SEARCH = record("jira-text-search", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a37", "jira", "search", [
  { input: "query", label: "Query", value: { type: "text", value: "checkout timeout" } },
  { input: "projects", label: "Projects", value: ["OPS", "SEC"] },
]);

export const JIRA_ISSUE_CREATE = record("jira-issue-create", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a32", "jira", "issue.create", [
  { input: "project", label: "Project", value: "OPS" },
  { input: "summary", label: "Summary", value: TRUNCATED_SUMMARY, truncated: true },
]);

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

/** An action that opts no inputs into audit. */
export const JIRA_PROJECT_LIST = record("jira-project-list", "5f0c2c3e-6a4b-4a8e-9a55-0d4c8e1f2a36", "jira", "project.list");

export const AUDIT_INPUT_RECORDS = [JIRA_SEARCH, JIRA_TEXT_SEARCH, JIRA_ISSUE_CREATE, JIRA_COMMENT_VIEW, GITLAB_ISSUE_SEARCH, GITLAB_ISSUE_VIEW, JIRA_PROJECT_LIST];
