// The matched portal route, and the account a self-service view acts on.
import { useMatches } from "react-router";
import type { PortalRouteHandle } from "./spaces";
import { useSession } from "./session";

export function useActiveRoute(): PortalRouteHandle | null {
  const matches = useMatches();
  for (let index = matches.length - 1; index >= 0; index -= 1) {
    const handle = matches[index]?.handle as PortalRouteHandle | undefined;
    if (handle?.space) return handle;
  }
  return null;
}

/**
 * The principal whose tokens, credentials, and access a view shows: the
 * signed-in user (`administered: false`), or a principal an administrator
 * opened from Principals.
 */
export type AccountSubject = { administered: boolean; principalId: string };

export function useSelfSubject(): AccountSubject {
  const { session } = useSession();
  return { administered: false, principalId: session.principal ?? "" };
}

export function adminSubject(principalId: string): AccountSubject {
  return { administered: true, principalId };
}
