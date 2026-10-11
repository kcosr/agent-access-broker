import type { ResourceTypeMetadata } from "../src/types";

/** Resource types as the broker registers them, in registration order (the first is the default for new resources). */
export const RESOURCE_TYPES: ResourceTypeMetadata[] = [
  { id: "git_repository", label: "Git repository", pluralLabel: "Git repositories", example: "engineering/payments", selectors: ["exact", "namespace", "all"], namespace: { label: "Repositories under a namespace", membersLabel: "Repositories", example: "engineering/platform" } },
  { id: "jira_project", label: "Jira project", pluralLabel: "Jira projects", example: "ENG", selectors: ["exact", "all"] },
  { id: "confluence_space", label: "Confluence space", pluralLabel: "Confluence spaces", example: "ENG", selectors: ["exact", "all"] },
  { id: "cloudbees_ci_job", label: "CloudBees CI job", pluralLabel: "CloudBees CI jobs", example: "team-ci/payments/build-api", selectors: ["exact", "namespace", "all"], namespace: { label: "Jobs under a controller or folder", membersLabel: "Jobs", example: "team-ci/payments" } },
  { id: "fake_project", label: "Fake project", pluralLabel: "Fake projects", example: "TEST", selectors: ["exact", "all"] },
  { id: "teams_notification_destination", label: "Teams notification destination", pluralLabel: "Teams notification destinations", example: "release-alerts", selectors: ["exact", "all"], attributes: [{ name: "webhookUrl", label: "Webhook URL", description: "Signed Microsoft Teams Workflows URL using the Anyone trigger setting", required: true, secret: true }] },
  { id: "oauth_collection", label: "OAuth test collection", pluralLabel: "OAuth test collections", example: "alpha", selectors: ["exact", "all"] }
];
