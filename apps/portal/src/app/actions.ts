// Runs user-triggered mutations with a pending marker; failures become an
// error toast (session failures are already handled by the session client).
import { useCallback, useState } from "react";
import { useSession } from "./session";

export function useActionRunner() {
  const { reportError } = useSession();
  const [pending, setPending] = useState<string | null>(null);
  const run = useCallback(
    async (key: string, action: () => Promise<unknown>) => {
      setPending(key);
      try {
        await action();
        return true;
      } catch (error) {
        reportError(error);
        return false;
      } finally {
        setPending((current) => (current === key ? null : current));
      }
    },
    [reportError]
  );
  return { run, pending, busy: pending !== null, isPending: (key: string) => pending === key };
}
