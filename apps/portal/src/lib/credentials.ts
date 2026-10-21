// Credential connections as the portal presents them: a principal's
// connections (one credential slot several services consume), its stored rows
// the configuration no longer selects, an administered principal's OAuth
// registrations, and the wording that names consumers.
import type { ConnectionConsumer, CredentialConnection, CredentialList, RemoteRevocation } from "../types";
import { plural } from "../workbench";

export const EMPTY_CREDENTIAL_LIST: CredentialList = { connections: [], retained: [] };

/**
 * An OAuth registration an administered principal's connections use, from
 * its administrator credential list: read-only, without the connection's
 * status or account, which only its owner's `GET /v1/oauth/connections` reports.
 */
export type AdministeredOAuth = {
  registration: string;
  /** The first connection's display name by connection ID, as the owner's row shows it. */
  displayName: string;
  /** The listed connections using the registration, in connection ID order. */
  connections: string[];
  consumers: ConnectionConsumer[];
  otherConsumers: number;
  /** Null while OAuth is inactive or the broker cannot read the state. */
  remoteRevocation: RemoteRevocation | null;
};

/**
 * One row per registration among a principal's OAuth-method connections,
 * like the owner's own list. A consuming service uses one connection, so the
 * registration's consumers are its connections' consumers together.
 */
export function administeredOAuthRegistrations(list: CredentialList): AdministeredOAuth[] {
  const registrations = new Map<string, AdministeredOAuth>();
  for (const connection of list.connections) {
    if (connection.method !== "oauth" || !connection.registration) continue;
    const listed = registrations.get(connection.registration);
    if (!listed) {
      registrations.set(connection.registration, {
        registration: connection.registration,
        displayName: connection.displayName,
        connections: [connection.connection],
        consumers: [...connection.consumers],
        otherConsumers: connection.otherConsumers,
        remoteRevocation: connection.remoteRevocation
      });
      continue;
    }
    listed.connections.push(connection.connection);
    listed.consumers.push(...connection.consumers);
    listed.otherConsumers += connection.otherConsumers;
    // Every connection reports the same registration's state.
    listed.remoteRevocation ??= connection.remoteRevocation;
  }
  return [...registrations.values()];
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
