// Credential connections as the portal presents them: a principal's
// connections (one credential slot several services consume), its stored rows
// the configuration no longer selects, and the wording that names consumers.
import type { ConnectionConsumer, ConnectionCredential, CredentialConnection, CredentialList, CredentialMetadata, CredentialTarget } from "../types";
import { plural } from "../workbench";

/** The stored name of every connection's token row. */
export const CONNECTION_CREDENTIAL_NAME = "default";

export const EMPTY_CREDENTIAL_LIST: CredentialList = { connections: [], retained: [] };

/** A stored row as its connection's active token. */
export function connectionCredential(row: CredentialMetadata): ConnectionCredential {
  const { service, name: _name, ...rest } = row;
  return { ...rest, connection: service };
}

/**
 * An administered principal's list, from its targets and its stored rows. A
 * target's active token is its `(connection, default)` row with the target's
 * profile; every other stored row is retained, deletable only by its ID.
 */
export function administeredCredentialList(targets: CredentialTarget[], stored: CredentialMetadata[]): CredentialList {
  const active = new Set<string>();
  const connections = targets.map<CredentialConnection>((target) => {
    const row = stored.find((item) => item.service === target.connection && item.name === CONNECTION_CREDENTIAL_NAME && item.profile === target.profile);
    if (row) active.add(row.credentialId);
    return {
      connection: target.connection,
      displayName: target.displayName,
      method: "token",
      consumers: target.consumers,
      otherConsumers: target.otherConsumers,
      profile: target.profile,
      credentialKind: target.credentialKind,
      registration: null,
      credential: row ? connectionCredential(row) : null
    };
  });
  return { connections, retained: stored.filter((row) => !active.has(row.credentialId)) };
}

/** The Credentials list key of an OAuth registration's row; a connection's row key is its ID. */
export const oauthRowKey = (registration: string) => `oauth:${registration}`;
/** The Credentials list key of a retained stored row. */
export const retainedRowKey = (credentialId: string) => `retained:${credentialId}`;

/** The connection `service` consumes among the principal's connections. */
export function connectionForService(list: CredentialList, service: string): CredentialConnection | undefined {
  return list.connections.find((connection) => connection.consumers.some((consumer) => consumer.service === service));
}

/** "GitLab REST, GitLab Git and 1 other service"; "1 other service" when none is named. */
export function consumerSummary(consumers: ConnectionConsumer[], otherConsumers: number): string {
  const names = consumers.map((consumer) => consumer.displayName);
  if (otherConsumers > 0) names.push(`${otherConsumers} other ${plural(otherConsumers, "service")}`);
  if (names.length <= 1) return names[0] ?? "";
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/** The consumers whose verification needs a repository (Git gateways). */
export function repositoryConsumers(consumers: ConnectionConsumer[]): ConnectionConsumer[] {
  return consumers.filter((consumer) => consumer.credentialVerificationInputs.includes("repository"));
}
